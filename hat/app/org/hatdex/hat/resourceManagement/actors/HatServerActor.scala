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

package org.hatdex.hat.resourceManagement.actors

import javax.inject.Inject

import scala.concurrent.Future
import scala.concurrent.duration._
import scala.util.{ Failure, Success }

import akka.actor._
import akka.pattern.pipe
import com.google.inject.assistedinject.Assisted
import org.hatdex.hat.api.service.RemoteExecutionContext
import org.hatdex.hat.resourceManagement._
import play.api.cache.AsyncCacheApi
import play.api.{ Configuration, Logger }

object HatServerActor {
  sealed trait HatServerActorMessage
  case class HatConnect() extends HatServerActorMessage
  case class HatConnected(hatServer: HatServer) extends HatServerActorMessage
  case class HatFailed(error: HatServerDiscoveryException) extends HatServerActorMessage
  case class HatRetrieve() extends HatServerActorMessage
  case class HatState(hatServer: HatServer) extends HatServerActorMessage

  trait Factory {
    def apply(hat: String): Actor
  }
}

class HatServerActor @Inject() (
    @Assisted hat: String,
    configuration: Configuration,
    hatDatabaseProvider: HatDatabaseProvider,
    hatKeyProvider: HatKeyProvider,
    cacheApi: AsyncCacheApi
  )(implicit ec: RemoteExecutionContext)
    extends Actor
    with Stash {
  import HatServerActor._
  private val log = Logger(this.getClass)
  val idleTimeout: FiniteDuration =
    configuration.get[FiniteDuration]("resourceManagement.serverIdleTimeout")

  def receive: Receive = {
    case _: HatRetrieve =>
      log.debug(s"RECEIVE HATRetrieve, stashing, connecting")
      stash()
      context.become(connecting)
      connect().pipeTo(self)
      context.setReceiveTimeout(idleTimeout)

    case message =>
      log.debug(s"RECEIVE Received unknown message: $message")
  }

  def connecting: Actor.Receive = {
    case HatConnected(server) =>
      unstashAll()
      context.become(connected(server))
      context.parent ! HatServerProviderActor.HatServerStarted(hat)
    case HatFailed(error) =>
      unstashAll()
      context.setReceiveTimeout(idleTimeout * 10)
      context.become(failed(error))
    case _: HatServerActorMessage =>
      stash()
  }

  def connected(server: HatServer): Actor.Receive = {
    case _: HatRetrieve =>
      log.debug(s"HAT $hat connected, replying")
      sender ! server
    case ReceiveTimeout =>
      log.info(s"HAT $hat idle, shutting down")
      shutdown(server)
      context.become(receive)
      context.parent ! HatServerProviderActor.HatServerStopped(hat)
    case message =>
      log.warn(s"CONNECTED Received unknown message: $message")
  }

  def failed(e: HatServerDiscoveryException): Actor.Receive = {
    case _: HatServerActorMessage =>
      log.debug(s"HAT $hat failed (${e.getMessage}), replying")
      sender ! e
    case ReceiveTimeout =>
      log.debug(s"HAT failed timeout, becoming neutral")
      context.become(receive)
    case message =>
      log.warn(s"FAILED Received unknown message: $message")
  }

  private def shutdown(server: HatServer): Future[Unit] = {
    cacheApi.remove(s"hatServer:${server.domain}")
    hatDatabaseProvider.shutdown(server.db)
  }

  private def connect(): Future[HatServerActorMessage] =
    server(hat)
      .map(hatConnected => HatConnected(hatConnected))
      .recover {
        case e: HatServerDiscoveryException => HatFailed(e)
      }

  private def server(hat: String): Future[HatServer] = {
    val server = for {
      privateKey <- hatKeyProvider.privateKey(hat)
      publicKey <- hatKeyProvider.publicKey(hat)
      db <- hatDatabaseProvider.database(hat)
      ownerEmail <- hatKeyProvider.ownerEmail(hat)
    } yield {
      val hatServer = HatServer(
        hat,
        hat.split('.').headOption.getOrElse(hat),
        ownerEmail,
        privateKey,
        publicKey,
        db
      )
      log.debug(s"HAT connection info $hatServer")
      hatServer
    }

    server onComplete {
      case Success(_) => log.debug(s"Server $hat information retrieved")
      case Failure(e) =>
        log.warn(
          s"Error while trying to fetch HAT $hat Server configuration: ${e.getMessage}"
        )
    }

    server
  }
}
