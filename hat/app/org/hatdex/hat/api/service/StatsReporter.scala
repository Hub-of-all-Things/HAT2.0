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

import javax.inject.{ Inject, Singleton }

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.concurrent.duration._
import scala.util.Failure

import akka.Done
import akka.actor.{ ActorSystem, Scheduler }
import com.mohiva.play.silhouette.api.services.AuthenticatorService
import com.mohiva.play.silhouette.impl.authenticators.JWTRS256Authenticator
import org.hatdex.dex.apiV2.DexClient
import io.dataswift.models.hat.{ DataStats, Platform }
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.dal.Tables._
import org.hatdex.hat.resourceManagement.HatServer
import org.hatdex.hat.utils.FutureRetries
import org.hatdex.libs.dal.HATPostgresProfile.api._
import play.api.libs.json.{ JsObject, Json }
import play.api.libs.ws.WSClient
import play.api.test.FakeRequest
import play.api.{ Configuration, Logger }

@Singleton
class StatsReporter @Inject() (
    wsClient: WSClient,
    configuration: Configuration,
    system: ActorSystem,
    usersService: UsersService,
    authenticatorService: AuthenticatorService[
      JWTRS256Authenticator,
      HatServer
    ]) {

  val logger: Logger = Logger(this.getClass)

  implicit private val scheduler: Scheduler = system.scheduler
  private val retryLimit =
    configuration.underlying.getInt("exchange.retryLimit")
  private val retryTime = FiniteDuration(
    configuration.underlying.getDuration("exchange.retryTime").toMillis,
    "millis"
  )
  private val statsBatchSize = 100

  private val dexClient = new DexClient(
    wsClient,
    configuration.underlying.getString("exchange.address"),
    configuration.underlying.getString("exchange.scheme"),
    "v1.1"
  )
  //  val defaultSsslConfig = AkkaSSLConfig()

  def reportStatistics(
      stats: Seq[DataStats]
    )(implicit server: HatServer): Future[Done] = {
    logger.debug(s"Reporting statistics: $stats")
    val logged = for {
      _ <- persistStats(stats)
      outstanding <- retrieveOutstandingStats()
      result <- reportPendingStatistics(outstanding)
    } yield result

    logged.andThen {
      case Failure(e) =>
        logger.error(s"Error while reporting stats: ${e.getMessage}")
      case _ => Done
    }
  }

  def registerOwnerConsent(
      applicationId: String
    )(implicit server: HatServer): Future[Done] =
    for {
      token <- validateToken()
      _ <- dexClient.registerTosConsent(token, applicationId)
    } yield Done

  protected def reportPendingStatistics(
      batch: Seq[DataStatsLogRow]
    )(implicit server: HatServer): Future[Done] =
    if (batch.isEmpty)
      Future.successful(Done)
    else {
      val statsBatch = batch.map(ModelTranslation.fromDbModel)
      for {
        _ <- FutureRetries.retry(
               uploadStats(statsBatch),
               FutureRetries.withDefault(List(), retryLimit, retryTime)
             )
        _ <- clearUploadedStats(batch)
        nextBatch <- retrieveOutstandingStats()
        result <- reportPendingStatistics(nextBatch)
      } yield result
    }

  private def clearUploadedStats(
      stats: Seq[DataStatsLogRow]
    )(implicit server: HatServer): Future[Done] =
    server.db
      .run(
        DataStatsLog.filter(_.statsId inSet stats.map(_.statsId).toSet).delete
      )
      .map(_ => Done)

  private def persistStats(
      stats: Seq[DataStats]
    )(implicit server: HatServer): Future[Seq[Long]] = {
    import io.dataswift.models.hat.json.DataStatsFormat.dataStatsFormat
    logger.debug(s"Persisting stats $stats")
    val dataStatsLogs = stats map { item =>
      DataStatsLogRow(0, Json.toJson(item))
    }
    server.db.run {
      (DataStatsLog returning DataStatsLog.map(_.statsId)) ++= dataStatsLogs
    }
  }

  private def retrieveOutstandingStats(
    )(implicit
      server: HatServer): Future[Seq[DataStatsLogRow]] =
    server.db.run {
      DataStatsLog.take(statsBatchSize).result
    }

  private def uploadStats(
      stats: Seq[DataStats]
    )(implicit server: HatServer): Future[Done] = {
    logger.debug(s"Uploading stats $stats")
    val uploaded = for {
      token <- validateToken()
      _ <- dexClient.postStats(token, stats)
    } yield Done

    uploaded.andThen {
      case Failure(e) =>
        logger.error(s"Failed to upload stats: ${e.getMessage}")
      case _ => Done
    }
  }

  private def platformUser()(implicit server: HatServer): Future[HatUser] =
    usersService.getUserByRole(Platform())(server).map(_.head)

  private def validateToken()(implicit server: HatServer): Future[String] = {
    //private def applicationToken()(implicit server: HatServer): Future[String] = {
    val resource = configuration.underlying.getString(
        "exchange.scheme"
      ) + configuration.underlying
            .getString("exchange.address")
    val customClaims = Map(
      "resource" -> Json.toJson(resource),
      "accessScope" -> Json.toJson("validate")
    )
    // Authentication service requires request header passed implicitly but does not use it for generating token
    implicit val fakeRequest = FakeRequest()
    for {
      user <- platformUser()
      authenticator <- authenticatorService.create(user.loginInfo)
      token <- authenticatorService.init(
                 authenticator.copy(customClaims = Some(JsObject(customClaims)))
               )
    } yield token
  }
}
