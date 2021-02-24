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
 * 2 / 2018
 */

package org.hatdex.hat.api.service.applications

import javax.inject.Inject

import scala.concurrent.Future
import scala.concurrent.duration._

import org.hatdex.dex.apiV2.DexClient
import org.hatdex.dex.apiV2.Errors.ApiException
import io.dataswift.models.hat.applications.Application
import org.hatdex.hat.api.service.RemoteExecutionContext
import play.api.cache.AsyncCacheApi
import play.api.libs.ws.WSClient
import play.api.{ Configuration, Logger }

trait TrustedApplicationProvider {
  def applications: Future[Seq[Application]]

  def application(id: String): Future[Option[Application]]
}

class TrustedApplicationProviderDex @Inject() (
    wsClient: WSClient,
    configuration: Configuration,
    cache: AsyncCacheApi
  )(implicit val rec: RemoteExecutionContext)
    extends TrustedApplicationProvider {

  private val logger = Logger(this.getClass)

  private val dexClient = new DexClient(
    wsClient,
    configuration.underlying.getString("exchange.address"),
    configuration.underlying.getString("exchange.scheme"),
    "v1.1"
  )

  private val includeUnpublished: Boolean =
    configuration.getOptional[Boolean]("exchange.beta").getOrElse(false)

  private val dexApplicationsCacheDuration: FiniteDuration = 30.minutes

  def applications: Future[Seq[Application]] =
    cache.getOrElseUpdate(
      "apps:dexApplications",
      dexApplicationsCacheDuration
    ) {
      dexClient.applications(includeUnpublished = includeUnpublished)
    }

  def application(id: String): Future[Option[Application]] =
    cache
      .getOrElseUpdate(
        s"apps:dex:$id",
        dexApplicationsCacheDuration
      ) {
        dexClient.application(id, None)
      }
      .map(Some(_))
      .recover {
        case e: ApiException =>
          logger.warn(s"Application config not found: ${e.getMessage}")
          None

        case e =>
          logger.error(s"Unexpected failure while fetching application. ${e.getMessage}")
          None
      }

}
