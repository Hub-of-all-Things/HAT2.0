/*
 * Copyright (C) 2017 HAT Data Exchange Ltd
 * SPDX-License-Identifier: AGPL-3.0
 *
 * This file is part of the Hub of All Things project (HAT).
 *
 * HAT is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, version 3 of
 * the License.
 *
 * HAT is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
 * the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General
 * Public License along with this program. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Written by Andrius Aucinas <andrius.aucinas@hatdex.org>
 * 2 / 2017
 */

package org.hatdex.hat.api.service

import javax.inject.Inject

import scala.concurrent.Future
import scala.util.{ Failure, Success }

import io.dataswift.models.hat.json.HatJsonFormats
import io.dataswift.models.hat.{ ApiHatFile, HatFileStatus }
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.dal.Tables._
import org.hatdex.hat.utils.Slugs
import org.hatdex.libs.dal.HATPostgresProfile.api._
import org.joda.time.LocalDateTime
import play.api.Logger
import play.api.libs.json.Json

class FileMetadataService @Inject() (implicit val ec: DalExecutionContext) {
  val logger: Logger = Logger(this.getClass)

  def getUniqueFileId(
      file: ApiHatFile
    )(implicit db: Database): Future[ApiHatFile] = {
    val extensionNormalized = file.name
      .split('.')
      .drop(1)
      .lastOption
      .map(Slugs.slugify)
      .map(ext => s".$ext")
      .getOrElse("")

    val nameNormalized = Slugs
      .slugify(s"${file.source}${file.name}")
      .stripSuffix(extensionNormalized.stripPrefix("."))

    val similarFilesSearch =
      HatFile.filter(t => t.id like s"$nameNormalized%$extensionNormalized")
    val eventualUniqueFilename = db
      .run(similarFilesSearch.result)
      .map(_.map(_.id))
      .map { similarFileNames =>
        Slugs.slugifyUnique(
          nameNormalized,
          Some(extensionNormalized),
          similarFileNames
        )
      }

    eventualUniqueFilename map { fn =>
      file.copy(fileId = Some(fn))
    }
  }

  def save(file: ApiHatFile)(implicit db: Database): Future[ApiHatFile] = {
    import HatJsonFormats.apiHatFileStatusFormat
    val dbFile = HatFileRow(
      file.fileId.get,
      file.name,
      file.source,
      file.dateCreated.map(_.toLocalDateTime).getOrElse(LocalDateTime.now()),
      file.lastUpdated.map(_.toLocalDateTime).getOrElse(LocalDateTime.now()),
      file.tags.map(_.toList),
      file.title,
      file.description,
      file.sourceURL,
      Json.toJson(file.status),
      file.contentPublic.getOrElse(false)
    )

    val updatedFileQuery = HatFile
      .joinLeft(HatFileAccess)
      .on(_.id === _.fileId)
      .filter(_._1.id === file.fileId.get)

    val fileQuery = (HatFile returning HatFile)
      .insertOrUpdate(dbFile)
      .andThen(updatedFileQuery.result)

    val result = db
      .run(fileQuery)
      .map(groupFilePermissions)
      .map(_.head)

    result.onComplete {
      case Success(_) => logger.debug(s"File $file saved")
      case Failure(e) =>
        logger.error(s"Error while saving file $file: ${e.getMessage}", e)
    }
    result
  }

  private def groupFilePermissions(
      files: Seq[(HatFileRow, Option[HatFileAccessRow])]): Iterable[ApiHatFile] =
    files.groupBy(_._1).map {
      case (file, permissions) =>
        ModelTranslation
          .fromDbModel(file)
          .copy(permissions = Some(permissions.unzip._2.flatten.map(ModelTranslation.fromDbModel)))
    }

  def grantAccess(
      file: ApiHatFile,
      user: HatUser,
      content: Boolean
    )(implicit db: Database): Future[Unit] = {
    val filePermissionRow =
      HatFileAccessRow(file.fileId.get, user.userId, content)
    db.run(HatFileAccess.forceInsert(filePermissionRow)).map(_ => ())
  }

  def restrictAccess(
      file: ApiHatFile,
      user: HatUser
    )(implicit db: Database): Future[Unit] = {
    val filePermissionRemove = HatFileAccess
      .filter(f => f.fileId === file.fileId.get && f.userId === user.userId)
      .delete
    db.run(filePermissionRemove).map(_ => ())
  }

  def grantAccessPattern(
      fileTemplate: ApiHatFile,
      user: HatUser,
      content: Boolean
    )(implicit db: Database): Future[Unit] = {
    val matchingFileQuery = for {
      file <- findFilesQuery(fileTemplate)
    } yield file.id

    db.run(matchingFileQuery.result) flatMap { fileIds =>
      val accessRows = fileIds map { fileId =>
        HatFileAccessRow(fileId, user.userId, content)
      }
      db.run(HatFileAccess.forceInsertAll(accessRows))
    } map { _ => () }
  }

  def restrictAccessPattern(
      fileTemplate: ApiHatFile,
      user: HatUser
    )(implicit db: Database): Future[Unit] = {
    val matchingFileQuery = for {
      file <- findFilesQuery(fileTemplate)
    } yield file.id

    val filePermissionRemove = HatFileAccess
      .filter(_.fileId in matchingFileQuery)
      .filter(_.userId === user.userId)
      .delete
    db.run(filePermissionRemove).map(_ => ())
  }

  def delete(fileId: String)(implicit db: Database): Future[ApiHatFile] = {
    import HatJsonFormats._
    val query = for {
      _ <- HatFile
             .filter(_.id === fileId)
             .map(v => (v.status, v.lastUpdated))
             .update((Json.toJson(HatFileStatus.Deleted()), LocalDateTime.now()))
      updatedFile <- HatFile.filter(_.id === fileId).result
    } yield updatedFile
    db.run(query).map(updated => ModelTranslation.fromDbModel(updated.head))
  }

  private def findFilesQuery(
      fileTemplate: ApiHatFile): Query[HatFile, HatFileRow, Seq] =
    HatFile.filter { t =>
      Some(fileTemplate.name)
        .filterNot(_.isEmpty)
        .fold(true.bind)(toTsVector(t.name) @@ plainToTsQuery(_)) &&
      Some(fileTemplate.source)
        .filterNot(_.isEmpty)
        .fold(true.bind)(toTsVector(t.source) @@ plainToTsQuery(_)) &&
      fileTemplate.status.fold(true.bind)(
        t.status.+>>("status") === _.status
      ) &&
      fileTemplate.title.fold(true.bind)(someTitle => toTsVector(t.title.getOrElse("")) @@ plainToTsQuery(someTitle)) &&
      fileTemplate.description.fold(true.bind)(
        toTsVector(t.description.getOrElse("")) @@ plainToTsQuery(_)
      ) &&
      fileTemplate.tags.fold(true.bind)(
        t.tags.getOrElse(List[String]()) @> _.toList
      )
    }

  def getById(
      fileId: String
    )(implicit db: Database): Future[Option[ApiHatFile]] = {
    val fileQuery = HatFile
      .joinLeft(HatFileAccess)
      .on(_.id === _.fileId)
      .filter(_._1.id === fileId)

    db.run(fileQuery.result)
      .map(groupFilePermissions)
      .map(_.headOption)
  }

  def search(
      fileTemplate: ApiHatFile
    )(implicit db: Database): Future[Seq[ApiHatFile]] = {
    val fileQuery = for {
      file <- findFilesQuery(fileTemplate)
                .joinLeft(HatFileAccess)
                .on(_.id === _.fileId)
    } yield file

    db.run(fileQuery.result)
      .map(groupFilePermissions)
      .map(_.toSeq)
  }
}
