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

package org.hatdex.hat.resourceManagement

import java.io.StringWriter
import java.security.interfaces.RSAPublicKey
import javax.inject.{ Inject, Named, Singleton }

import scala.concurrent.Future
import scala.concurrent.duration._

import akka.actor.ActorRef
import akka.pattern.ask
import akka.util.Timeout
import com.mohiva.play.silhouette.api.services.DynamicEnvironmentProviderService
import org.bouncycastle.util.io.pem.{ PemObject, PemWriter }
import org.hatdex.hat.api.service.RemoteExecutionContext
import org.hatdex.hat.resourceManagement.actors.HatServerProviderActor
import org.hatdex.hat.utils.LoggingProvider
import play.api.Configuration
import play.api.cache.{ AsyncCacheApi, NamedCache }
import play.api.mvc.Request

trait HatServerProvider extends DynamicEnvironmentProviderService[HatServer] {
  def retrieve[B](request: Request[B]): Future[Option[HatServer]]
  def retrieve(hatAddress: String): Future[Option[HatServer]]
  def toString(publicKey: RSAPublicKey): String = {
    val pemObject            = new PemObject("PUBLIC KEY", publicKey.getEncoded)
    val stringPemWriter      = new StringWriter()
    val pemWriter: PemWriter = new PemWriter(stringPemWriter)
    pemWriter.writeObject(pemObject)
    pemWriter.flush()
    val pemPublicKey = stringPemWriter.toString
    pemPublicKey
  }
}

@Singleton
class HatServerProviderImpl @Inject() (
    configuration: Configuration,
    @NamedCache("hatserver-cache") cache: AsyncCacheApi,
    loggingProvider: LoggingProvider,
    @Named("hatServerProviderActor") serverProviderActor: ActorRef
  )(implicit
    val ec: RemoteExecutionContext)
    extends HatServerProvider {

  private val logger = loggingProvider.logger(this.getClass)

  def retrieve[B](request: Request[B]): Future[Option[HatServer]] = {
    val hatAddress =
      request.host //.split(':').headOption.getOrElse(request.host)
    retrieve(hatAddress)
  }

  implicit val timeout: Timeout = configuration.get[FiniteDuration](
    "resourceManagement.serverProvisioningTimeout"
  )
  implicit val serverInfoTimeout: Duration =
    configuration.get[FiniteDuration]("resourceManagement.serverIdleTimeout")

  def retrieve(hatAddress: String): Future[Option[HatServer]] = {
    logger.info(s"HatServiceProvider.retrieve: looking up hatAddress: server:${hatAddress}")

    cache
      .get[HatServer](s"server:$hatAddress")
      .flatMap {
        case Some(server) => Future.successful(Some(server))
        case _ =>
          (serverProviderActor ? HatServerProviderActor.HatServerRetrieve(
                hatAddress
              )) map {
              case server: HatServer =>
                logger.info(s"Got back server $server")
                cache.set(s"server:$hatAddress", server, serverInfoTimeout)
                Some(server)
              case error: HatServerDiscoveryException =>
                logger.warn(s"Got back error $error")
                throw error
              case message =>
                logger.warn(
                  s"Unknown message $message from HAT Server provider actor"
                )
                val error = new HatServerDiscoveryException("Unknown message")
                throw error
            } recoverWith {
              case e =>
                logger.warn(
                  s"Error while retrieving HAT $hatAddress info: ${e.getMessage} ${e.getStackTrace()}"
                )
                val error = new HatServerDiscoveryException(
                  "HAT Server info retrieval failed",
                  e
                )
                throw error
            }
      }
  }
}
