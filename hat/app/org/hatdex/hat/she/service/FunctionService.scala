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
 * 11 / 2017
 */

package org.hatdex.hat.she.service

import java.security.MessageDigest
import javax.inject.Inject

import scala.concurrent.duration._
import scala.concurrent.{ ExecutionContext, Future }
import scala.util.{ Failure, Success }

import akka.Done
import io.dataswift.models.hat.json.{ ApplicationJsonProtocol, DataFeedItemJsonProtocol }
import io.dataswift.models.hat.{ EndpointData, Owner }
import org.hatdex.hat.api.service.UsersService
import org.hatdex.hat.api.service.richData.RichDataService
import org.hatdex.hat.dal.Tables._
import org.hatdex.hat.resourceManagement.HatServer
import org.hatdex.hat.she.models._
import org.hatdex.libs.dal.HATPostgresProfile.api._
import org.joda.time.DateTime
import play.api.Logger
import play.api.libs.json.Json

class FunctionService @Inject() (
    functionRegistry: FunctionExecutableRegistry,
    dataService: RichDataService,
    usersService: UsersService
  )(implicit
    ec: ExecutionContext) {

  private val logger                                   = Logger(this.getClass)
  private val functionExecutionTimeout: FiniteDuration = 5.minutes
  implicit private def hatServer2db(implicit hatServer: HatServer): Database =
    hatServer.db

  protected def mergeRegisteredSaved(
      registeredFunctions: Seq[FunctionConfiguration],
      savedFunctions: Seq[FunctionConfiguration]): Seq[FunctionConfiguration] = {
    val registered: Map[String, FunctionConfiguration] =
      registeredFunctions.map(r => r.id -> r).toMap
    val saved: Map[String, FunctionConfiguration] =
      savedFunctions.map(r => r.id -> r).toMap

    val functions =
      for ((k, v) <- saved ++ registered)
        yield k -> (if ((saved contains k) && (registered contains k))
                      saved(k).update(v)
                    else v)

    functions.values.toSeq
  }

  def all(
      active: Boolean
    )(implicit db: Database): Future[Seq[FunctionConfiguration]] =
    for {
      registeredFunctions <- Future.successful(
                               functionRegistry.getSeq[FunctionExecutable].map(_.configuration)
                             )
      savedFunctions <- saved()
    } yield mergeRegisteredSaved(registeredFunctions, savedFunctions)
      .filter(f => !active || f.status.enabled && f.status.available) // only return enabled ones if filtering is on

  def get(
      id: String
    )(implicit db: Database): Future[Option[FunctionConfiguration]] = {
    val query = for {
      (function, status) <- SheFunction
                              .filter(_.id === id)
                              .joinLeft(SheFunctionStatus)
                              .on(_.id === _.id)
      bundle <- function.dataBundlesFk
    } yield (function, status, bundle)

    for {
      r <- Future.successful(
             functionRegistry
               .getSeq[FunctionExecutable]
               .map(_.configuration)
               .filter(_.id == id)
           )
      f <- db.run(query.take(1).result)
             .map(
               _.map(f =>
                 FunctionConfiguration(
                   f._1,
                   f._2,
                   f._3,
                   available = r.exists(rf => rf.id == f._1.id && rf.status.available)
                 )
               )
             )
    } yield mergeRegisteredSaved(r, f).headOption
  }

  def saved()(implicit db: Database): Future[Seq[FunctionConfiguration]] = {
    val query = for {
      (function, status) <- SheFunction.joinLeft(SheFunctionStatus).on(_.id === _.id)
      bundle <- function.dataBundlesFk
    } yield (function, status, bundle)

    for {
      r <- Future.successful(
             functionRegistry.getSeq[FunctionExecutable].map(_.configuration)
           )
      f <- db.run(query.result)
             .map(
               _.map(f =>
                 FunctionConfiguration(
                   f._1,
                   f._2,
                   f._3,
                   available = r.exists(rf => rf.id == f._1.id && rf.status.available)
                 )
               )
             )
    } yield f
  }

  def save(
      configuration: FunctionConfiguration
    )(implicit db: Database): Future[FunctionConfiguration] = {
    logger.debug(s"Save function configuration $configuration")
    import io.dataswift.models.hat.json.RichDataJsonFormats.propertyQueryFormat
    import org.hatdex.hat.she.models.FunctionConfigurationJsonProtocol.triggerFormat
    import ApplicationJsonProtocol.formattedTextFormat
    import DataFeedItemJsonProtocol.feedItemFormat
    import ApplicationJsonProtocol.applicationGraphicsFormat

    val functionRow = SheFunctionRow(
      configuration.id,
      Json.toJson(configuration.info.description),
      Json.toJson(configuration.trigger),
      configuration.dataBundle.name,
      configuration.info.headline,
      configuration.info.dataPreview.map(dp => Json.toJson(dp)),
      configuration.info.dataPreviewEndpoint,
      Json.toJson(configuration.info.graphics),
      configuration.info.name,
      configuration.info.version.toString(),
      configuration.info.termsUrl,
      configuration.developer.id,
      configuration.developer.name,
      configuration.developer.url,
      configuration.developer.country,
      configuration.info.versionReleaseDate,
      configuration.info.supportContact
    )

    val bundleRow = DataBundlesRow(
      configuration.dataBundle.name,
      Json.toJson(configuration.dataBundle.bundle)
    )
    val statusRow = SheFunctionStatusRow(
      configuration.id,
      configuration.status.enabled,
      configuration.status.lastExecution,
      configuration.status.executionStarted
    )

    db.run(
      DBIO
        .seq(
          DataBundles.insertOrUpdate(bundleRow),
          SheFunction.insertOrUpdate(functionRow),
          SheFunctionStatus.insertOrUpdate(statusRow)
        )
        .transactionally
    ).flatMap(_ => get(configuration.id))
      .map(_.get)
  }

  def run(
      configuration: FunctionConfiguration,
      startTime: Option[DateTime],
      useAll: Boolean
    )(implicit hatServer: HatServer): Future[Done] = {
    val executionTime = DateTime.now()
    logger.info(
      s"[${hatServer.domain}] SHE function [${configuration.id}] run @$executionTime (previously $startTime)"
    )
    functionRegistry
      .get[FunctionExecutable](configuration.id)
      .map { function: FunctionExecutable =>
        val fromDate  = startTime.orElse(Some(DateTime.now().minusMonths(6)))
        val untilDate = Some(DateTime.now().plusMonths(3))
        val dataBundleTimeFilter =
          if (useAll)
            None
          else
            configuration.status.lastExecution

        val executionResult = for {
          _ <- markExecuting(configuration)
          bundle <- function.bundleFilterByDate(fromDate, untilDate)
          data <- dataService.bundleData(
                    bundle,
                    createdAfter = dataBundleTimeFilter
                  ) // Get all bundle data from a specific date until now
          response <- function
                        .execute(
                          configuration,
                          Request(data, linkRecords = true)
                        ) // Execute the function
                        .map(
                          removeDuplicateData
                        ) // Remove duplicate data in case some records mapped onto the same values when transformed
          // TODO handle cases when function runs for longer and connection to DB needs to be reestablished
          owner <- usersService
                     .getUserByRole(Owner())
                     .map(
                       _.head
                     ) // Fetch the owner user - functions run on their behalf
          _ <- dataService.saveDataGroups(
                 owner.userId,
                 response.map(r =>
                   (
                     r.data.map(
                       EndpointData(
                         s"${r.namespace}/${r.endpoint}",
                         None,
                         None,
                         None,
                         _,
                         None
                       )
                     ),
                     r.linkedRecords
                   )
                 ),
                 skipErrors = true
               )
          _ <- markCompleted(configuration)
        } yield (data.values.map(_.length).sum, Done)

        executionResult
          .andThen({
            case Success((totalRecords, _)) =>
              logger.info(
                s"[${hatServer.domain}] SHE function [${configuration.id}] finished, generated $totalRecords records"
              )
            case Failure(e) =>
              logger.error(
                s"[${hatServer.domain}] SHE function [${configuration.id}] error: ${e.getMessage}"
              )
          })
          .map(_._2)

      } getOrElse {
      Future.failed(
        SHEFunctionNotAvailableException(
          "The requested function is not available"
        )
      )
    }
  }

  private def markExecuting(
      function: FunctionConfiguration
    )(implicit hatServer: HatServer): Future[Done] = {
    val notExecuting = SheFunctionStatus
      .filter(_.id === function.id)
      .filter(s =>
        s.lastExecution > DateTime
              .now()
              .minus(functionExecutionTimeout.toMillis)
      )
      .result
      .flatMap(r =>
        if (r.isEmpty)
          DBIO.successful("No current execution")
        else
          DBIO.failed(
            SHEFunctionBusyExecutingException("The function is being executed")
          )
      )

    val mark = SheFunctionStatus
      .filter(_.id === function.id)
      .map(s => s.executionStarted)
      .update(Some(DateTime.now()))

    hatServer.db
      .run(DBIO.seq(notExecuting, mark).transactionally)
      .map(_ => Done)
  }

  private def markCompleted(
      function: FunctionConfiguration
    )(implicit hatServer: HatServer): Future[Done] = {
    val now = DateTime.now()
    logger.info(
      s"[${hatServer.domain}] Successfully executed function ${function.id} at $now"
    )

    val update = SheFunctionStatus
      .filter(_.id === function.id)
      .map(s => (s.executionStarted, s.lastExecution))
      .update((None, Some(now)))

    hatServer.db
      .run(update)
      .map(_ => Done)
  }

  //TODO: expensive operation!
  private def removeDuplicateData(response: Seq[Response]): Seq[Response] = {
    val md = MessageDigest.getInstance("SHA-256")
    response
      .flatMap { r =>
        r.data.headOption.map { data =>
          val digest = md.digest(data.toString().getBytes)
          (BigInt(digest), r)
        }
      }
      .sortBy(_._1)
      .foldRight(Seq[(BigInt, Response)]())({
        case (e, ls) if ls.isEmpty || ls.head._1 != e._1 => e +: ls
        case (_, ls)                                     => ls
      })
      .unzip
      ._2 // Drop the digest
  }
}
