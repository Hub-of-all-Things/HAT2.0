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
package org.hatdex.hat.phata.controllers

import javax.inject.Inject

import scala.concurrent.ExecutionContext.Implicits.global

import com.mohiva.play.silhouette.api.Silhouette
import controllers.{ Assets, AssetsFinder, AssetsFinderProvider }
import io.dataswift.models.hat.json.{ HatJsonFormats, RichDataJsonFormats }
import io.dataswift.models.hat.EndpointDataBundle
import org.hatdex.hat.api.service.richData.{ RichBundleService, RichDataService }
import org.hatdex.hat.authentication.{ HatApiAuthEnvironment, HatApiController }
import play.api.cache.{ Cached, CachedBuilder }
import play.api.libs.json.Json
import play.api.mvc._
import play.api.{ Configuration, Logger }

class Phata @Inject() (
    components: ControllerComponents,
    assets: Assets,
    assetsFinder: AssetsFinderProvider,
    cached: Cached,
    configuration: Configuration,
    silhouette: Silhouette[HatApiAuthEnvironment],
    bundleService: RichBundleService,
    dataService: RichDataService)
    extends HatApiController(components, silhouette)
    with HatJsonFormats
    with RichDataJsonFormats {

  implicit val af: AssetsFinder = assetsFinder.get

  private val logger = Logger(this.getClass)

  val indefiniteSuccessCaching: CachedBuilder = cached
    .status(req => s"${req.host}${req.path}", 200)
    .includeStatus(404, 600)

  val csp: Map[String, String] = configuration
    .get[String]("play.filters.headers.contentSecurityPolicy")
    .split(';')
    .map(_.trim)
    .map { p =>
      val splits = p.split(' ')
      splits.head -> splits.tail.mkString(" ")
    }
    .toMap

  def dashboard(path: String): EssentialAction = {
    logger.debug(s"Serving PDA Dashboard v4 on path [$path]")
    assets.at("index.html")
  }

  def profile: Action[AnyContent] =
    UserAwareAction.async { implicit request =>
      val defaultBundleDefinition = Json
        .parse(configuration.get[String]("phata.defaultBundle"))
        .as[EndpointDataBundle]
      for {
        bundle <- bundleService
                    .bundle(defaultBundleDefinition.name)
                    .map(_.getOrElse(defaultBundleDefinition))
        data <- dataService.bundleData(bundle, None, None, None)
      } yield Ok(Json.toJson(data))
    }
}
