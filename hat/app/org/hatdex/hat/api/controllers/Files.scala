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

package org.hatdex.hat.api.controllers

import java.util.UUID
import javax.inject.Inject

import scala.concurrent.{ ExecutionContext, Future }

import com.mohiva.play.silhouette.api.Silhouette
import io.dataswift.models.hat.json.HatJsonFormats
import io.dataswift.models.hat._
import io.dataswift.models.hat.applications.HatApplication
import org.hatdex.hat.api.service.applications.ApplicationsService
import org.hatdex.hat.api.service.{ FileManager, FileMetadataService, UsersService }
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.authentication.{ ContainsApplicationRole, HatApiAuthEnvironment, HatApiController, WithRole }
import org.hatdex.hat.utils.HatBodyParsers
import org.joda.time.DateTime
import play.api.Logger
import play.api.libs.json.Json
import play.api.mvc._

class Files @Inject() (
    components: ControllerComponents,
    parsers: HatBodyParsers,
    silhouette: Silhouette[HatApiAuthEnvironment],
    fileMetadataService: FileMetadataService,
    fileManager: FileManager,
    usersService: UsersService,
    implicit val ec: ExecutionContext,
    implicit val applicationsService: ApplicationsService)
    extends HatApiController(components, silhouette)
    with HatJsonFormats {

  val logger: Logger = Logger(this.getClass)

  def startUpload: Action[ApiHatFile] =
    SecuredAction(
      WithRole(DataCredit(""), Owner()) || ContainsApplicationRole(
          ManageFiles("*"),
          Owner()
        )
    ).async(parsers.json[ApiHatFile]) { implicit request =>
      val cleanFile = request.body.copy(
        fileId = None,
        status = Some(HatFileStatus.New()),
        contentUrl = None,
        contentPublic = Some(false),
        permissions = None
      )
      val eventualUploadUrl = for {
        fileWithId <- fileMetadataService.getUniqueFileId(cleanFile)
        savedFile <- fileMetadataService.save(fileWithId)
        uploadUrl <- fileManager.getUploadUrl(
                       fileWithId.fileId.get,
                       fileWithId.contentType
                     )
        _ <- fileMetadataService.grantAccess(
               savedFile,
               request.identity,
               content = true
             )
        file <- fileMetadataService.getById(savedFile.fileId.get).map(_.get)
      } yield (file, uploadUrl)

      eventualUploadUrl
        .map {
          case (savedFile, url) =>
            Ok(Json.toJson(savedFile.copy(contentUrl = Some(url))))
        }
        .recoverWith {
          case e =>
            logger.error(s"Error uploading file: ${e.getMessage}", e)
            Future.successful(
              BadRequest(
                Json.toJson(ErrorMessage("Error uploading file", e.getMessage))
              )
            )
        }
    }

  def completeUpload(fileId: String): Action[AnyContent] =
    SecuredAction(
      WithRole(DataCredit(""), Owner()) || ContainsApplicationRole(
          ManageFiles("*"),
          Owner()
        )
    ).async { implicit request =>
      request2ApplicationStatus(request) flatMap { maybeAsApplication =>
        fileMetadataService.getById(fileId) flatMap {
          case Some(file) if fileContentAccessAllowed(file, maybeAsApplication) =>
            logger.debug(s"Marking $file complete ")
            val eventuallyCompleted = for {
              fileSize <- fileManager.getFileSize(file.fileId.get)
              completed <- fileMetadataService.save(
                             file.copy(status = Some(HatFileStatus.Completed(fileSize)))
                           ) if fileSize > 0
              _ = completed // Workaround scala/bug#11175 -Ywarn-unused:params false positive
            } yield completed

            eventuallyCompleted map { completed =>
              Ok(Json.toJson(completed))
            } recover {
              case e =>
                logger.warn(s"Could not complete file upload: ${e.getMessage}")
                BadRequest(
                  Json.toJson(
                    ErrorMessage(
                      "File not available",
                      s"Not fully uploaded file can not be completed"
                    )
                  )
                )
            }

          case _ =>
            Future.successful(
              NotFound(
                Json.toJson(
                  ErrorMessage("No such file", s"File $fileId not found")
                )
              )
            )
        }
      }
    }

  private def fileContentAccessAllowed(
      file: ApiHatFile,
      appStatus: Option[HatApplication]
    )(implicit user: HatUser,
      authenticator: HatApiAuthEnvironment#A): Boolean =
    appStatus.exists(
      ContainsApplicationRole.isAuthorized(
        user,
        _,
        authenticator,
        ManageFiles("*")
      )
    ) ||
      WithRole.isAuthorized(user, authenticator, Owner()) ||
      (file.status.exists(_.isInstanceOf[HatFileStatus.Completed]) &&
        file.permissions.isDefined &&
        file.permissions.get.exists(p => p.userId == user.userId && p.contentReadable))

  def getDetail(fileId: String): Action[AnyContent] =
    SecuredAction.async { implicit request =>
      val fileWithApp = for {
        metadata <- fileMetadataService.getById(fileId)
        app <- request2ApplicationStatus(request)
      } yield (metadata, app)
      fileWithApp flatMap {
        case (Some(file), app) if fileContentAccessAllowed(file, app) =>
          fileManager
            .getContentUrl(file.fileId.get)
            .map(url => file.copy(contentUrl = Some(url)))
            .map(filePermissionsCleaned)
            .map(file => Ok(Json.toJson(file)))
        case (Some(file), app) if fileAccessAllowed(file, app) =>
          Future.successful(Ok(Json.toJson(filePermissionsCleaned(file))))
        case (Some(_), _) =>
          Future.successful(
            NotFound(
              Json.toJson(
                ErrorMessage(
                  "File not available",
                  s"File $fileId not available - unauthorized or file incomplete"
                )
              )
            )
          )
        case (None, _) =>
          Future.successful(
            NotFound(
              Json.toJson(
                ErrorMessage("No such file", s"File $fileId not found")
              )
            )
          )
      }
    }

  def getContent(fileId: String): Action[AnyContent] =
    UserAwareAction.async { implicit request =>
      val fileWithApp = for {
        metadata <- fileMetadataService.getById(fileId)
        app <- request2ApplicationStatus(request)
      } yield (metadata, request.identity, request.authenticator, app)

      fileWithApp flatMap {
        case (Some(file), _, _, _) if file.contentPublic.contains(true) =>
          fileManager
            .getContentUrl(file.fileId.get)
            .map(url => Redirect(url))
        case (Some(file), Some(user), Some(authenticator), app)
            if fileContentAccessAllowed(file, app)(user, authenticator) =>
          fileManager
            .getContentUrl(file.fileId.get)
            .map(url => Redirect(url))
        case _ =>
          Future.successful(NotFound(""))
      }
    }

  def listFiles(): Action[ApiHatFile] =
    SecuredAction.async(parsers.json[ApiHatFile]) { implicit request =>
      request2ApplicationStatus(request) flatMap { maybeAsApplication =>
        fileMetadataService
          .search(request.body)
          .map(_.filter(fileAccessAllowed(_, maybeAsApplication)))
          .flatMap { foundFiles =>
            val fileContentsEventual = foundFiles map { file =>
              if (fileContentAccessAllowed(file, maybeAsApplication))
                fileManager
                  .getContentUrl(file.fileId.get)
                  .map(url => file.copy(contentUrl = Some(url)))
                  .map(filePermissionsCleaned)
              else
                Future.successful(filePermissionsCleaned(file))
            }
            Future
              .sequence(fileContentsEventual)
              .map(files => Ok(Json.toJson(files)))
          }
      }
    }

  private def fileAccessAllowed(
      file: ApiHatFile,
      appStatus: Option[HatApplication]
    )(implicit user: HatUser,
      authenticator: HatApiAuthEnvironment#A): Boolean =
    appStatus.exists(
      ContainsApplicationRole.isAuthorized(
        user,
        _,
        authenticator,
        ManageFiles(file.source)
      )
    ) ||
      WithRole.isAuthorized(user, authenticator, Owner()) ||
      (file.permissions.isDefined &&
        file.permissions.get.exists(_.userId == user.userId))

  private def filePermissionsCleaned(
      file: ApiHatFile
    )(implicit user: HatUser,
      authenticator: HatApiAuthEnvironment#A): ApiHatFile =
    if (WithRole.isAuthorized(user, authenticator, Owner()))
      file
    else
      file.copy(permissions = None)

  def updateFile(fileId: String): Action[ApiHatFile] =
    SecuredAction.async(parsers.json[ApiHatFile]) { implicit request =>
      request2ApplicationStatus(request) flatMap { maybeAsApplication =>
        fileMetadataService.getById(fileId) flatMap {
          case Some(file) if fileContentAccessAllowed(file, maybeAsApplication) =>
            val updatedFile = file.copy(
              name = request.body.name,
              lastUpdated = request.body.lastUpdated.orElse(Some(DateTime.now())),
              tags = request.body.tags,
              title = request.body.title,
              description = request.body.description
            )

            fileMetadataService.save(updatedFile).map(f => Ok(Json.toJson(f)))
          case _ =>
            Future.successful(
              NotFound(
                Json.toJson(
                  ErrorMessage("No such file", s"File $fileId not found")
                )
              )
            )
        }
      }
    }

  def deleteFile(fileId: String): Action[AnyContent] =
    SecuredAction(
      WithRole(Owner()) || ContainsApplicationRole(Owner(), ManageFiles("*"))
    ).async { implicit request =>
      fileMetadataService.getById(fileId) flatMap {
        case Some(file) =>
          val eventuallyDeleted = for {
            _ <- fileManager.deleteContents(file.fileId.get)
            deleted <- fileMetadataService.save(
                         file.copy(status = Some(HatFileStatus.Deleted()))
                       )
          } yield deleted
          eventuallyDeleted.map(file => Ok(Json.toJson(file)))
        case None =>
          Future.successful(
            NotFound(
              Json.toJson(
                ErrorMessage("No such file", s"File $fileId not found")
              )
            )
          )
      }
    }

  def allowAccess(
      fileId: String,
      userId: UUID,
      content: Boolean): Action[AnyContent] =
    SecuredAction(
      WithRole(Owner()) || ContainsApplicationRole(Owner(), ManageFiles("*"))
    ).async { implicit request =>
      request2ApplicationStatus(request) flatMap { maybeAsApplication =>
        fileMetadataService.getById(fileId) flatMap {
          case Some(file) if fileAccessAllowed(file, maybeAsApplication) =>
            val eventuallyGranted = for {
              user <- usersService.getUser(userId) if user.isDefined
              _ <- fileMetadataService.grantAccess(file, user.get, content)
              updated <- fileMetadataService.getById(fileId).map(_.get)
            } yield updated
            eventuallyGranted.map(f => Ok(Json.toJson(f)))
          case None =>
            Future.successful(
              NotFound(
                Json.toJson(
                  ErrorMessage("No such file", s"File $fileId not found")
                )
              )
            )
        }
      }
    }

  def restrictAccess(
      fileId: String,
      userId: UUID): Action[AnyContent] =
    SecuredAction(
      WithRole(Owner()) || ContainsApplicationRole(Owner(), ManageFiles("*"))
    ).async { implicit request =>
      request2ApplicationStatus(request) flatMap { maybeAsApplication =>
        fileMetadataService.getById(fileId) flatMap {
          case Some(file) if fileAccessAllowed(file, maybeAsApplication) =>
            val eventuallyGranted = for {
              user <- usersService.getUser(userId) if user.isDefined
              _ <- fileMetadataService.restrictAccess(file, user.get)
              updated <- fileMetadataService.getById(fileId).map(_.get)
            } yield updated
            eventuallyGranted.map(f => Ok(Json.toJson(f)))
          case None =>
            Future.successful(
              NotFound(
                Json.toJson(
                  ErrorMessage("No such file", s"File $fileId not found")
                )
              )
            )
        }
      }
    }

  def changePublicAccess(
      fileId: String,
      public: Boolean): Action[AnyContent] =
    SecuredAction(
      WithRole(Owner()) || ContainsApplicationRole(Owner(), ManageFiles("*"))
    ).async { implicit request =>
      request2ApplicationStatus(request) flatMap { maybeAsApplication =>
        fileMetadataService.getById(fileId) flatMap {
          case Some(file) if fileAccessAllowed(file, maybeAsApplication) =>
            val eventuallyGranted = for {
              _ <- fileMetadataService.save(
                     file.copy(contentPublic = Some(public))
                   )
              updated <- fileMetadataService.getById(fileId).map(_.get)
            } yield updated
            eventuallyGranted.map(f => Ok(Json.toJson(f)))
          case None =>
            Future.successful(
              NotFound(
                Json.toJson(
                  ErrorMessage("No such file", s"File $fileId not found")
                )
              )
            )
        }
      }
    }

  def allowAccessPattern(
      userId: UUID,
      content: Boolean): Action[ApiHatFile] =
    SecuredAction(
      WithRole(Owner()) || ContainsApplicationRole(Owner(), ManageFiles("*"))
    ).async(parsers.json[ApiHatFile]) { implicit request =>
      val eventuallyAllowedFiles = for {
        user <- usersService.getUser(userId) if user.isDefined
        _ <- fileMetadataService.grantAccessPattern(
               request.body,
               user.get,
               content
             )
        matchingFiles <- fileMetadataService.search(request.body)
      } yield matchingFiles

      eventuallyAllowedFiles map { files =>
        Ok(Json.toJson(files))
      } recover {
        case e =>
          logger.error(
            s"Error while granting access to a pattern of files: ${e.getMessage}",
            e
          )
          BadRequest(
            Json.toJson(
              ErrorMessage(
                "Could not grant access",
                "No such user or unexpected error while granting access"
              )
            )
          )
      }
    }

  def restrictAccessPattern(userId: UUID): Action[ApiHatFile] =
    SecuredAction(
      WithRole(Owner()) || ContainsApplicationRole(Owner(), ManageFiles("*"))
    ).async(parsers.json[ApiHatFile]) { implicit request =>
      val eventuallyAllowedFiles = for {
        user <- usersService.getUser(userId) if user.isDefined
        _ <- fileMetadataService.restrictAccessPattern(request.body, user.get)
        matchingFiles <- fileMetadataService.search(request.body)
      } yield matchingFiles

      eventuallyAllowedFiles map { files =>
        Ok(Json.toJson(files))
      } recover {
        case e =>
          logger.error(
            s"Error while granting access to a pattern of files: ${e.getMessage}",
            e
          )
          BadRequest(
            Json.toJson(
              ErrorMessage(
                "Could not grant access",
                "No such user or unexpected error while granting access"
              )
            )
          )
      }
    }

}
