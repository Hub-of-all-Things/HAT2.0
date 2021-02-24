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

import scala.concurrent.duration._
import scala.concurrent.{ ExecutionContext, Future }

import org.hatdex.hat.resourceManagement.models.HatSignup
import play.api.cache.AsyncCacheApi
import play.api.http.Status._
import play.api.libs.json.{ JsError, JsSuccess }
import play.api.libs.ws.{ WSClient, WSRequest, WSResponse }
import play.api.{ Configuration, Logger }

trait MillinerHatSignup {
  val logger: Logger
  val ws: WSClient
  val configuration: Configuration
  val schema: String =
    configuration.get[String]("resourceManagement.millinerAddress") match {
      case address if address.startsWith("https") => "https://"
      case address if address.startsWith("http")  => "http://"
      case _                                      => "https://"
    }

  val millinerAddress: String = configuration
    .get[String]("resourceManagement.millinerAddress")
    .stripPrefix("http://")
    .stripPrefix("https://")
  val hatSharedSecret: String =
    configuration.get[String]("resourceManagement.hatSharedSecret")

  val cache: AsyncCacheApi

  def getHatSignup(
      hatAddress: String
    )(implicit ec: ExecutionContext): Future[HatSignup] =
    // Cache the signup information for subsequent calls (For private/public key and database details)
    cache.getOrElseUpdate[HatSignup](s"configuration:$hatAddress") {
      val request: WSRequest = ws
        .url(s"$schema$millinerAddress/api/manage/configuration/$hatAddress")
        .withVirtualHost(millinerAddress)
        .withHttpHeaders(
          "Accept" -> "application/json",
          "X-Auth-Token" -> hatSharedSecret
        )

      val futureResponse: Future[WSResponse] = request.get()
      futureResponse.map { response =>
        response.status match {
          case OK =>
            response.json.validate[HatSignup] match {
              case signup: JsSuccess[HatSignup] =>
                logger.debug(s"Got back configuration: ${signup.value}")
                cache.set(s"configuration:$hatAddress", signup.value, 1.minute)
                signup.value
              case e: JsError =>
                logger.error(s"Parsing HAT configuration failed: $e")
                throw new HatServerDiscoveryException(
                  "Fetching HAT configuration failed"
                )
            }
          case _ =>
            logger.error(s"Fetching HAT configuration failed: ${response.body}")
            throw new HatServerDiscoveryException(
              "Fetching HAT configuration failed"
            )
        }
      }
    }

}
