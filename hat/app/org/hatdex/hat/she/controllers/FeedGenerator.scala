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

package org.hatdex.hat.she.controllers

import javax.inject.Inject

import scala.concurrent.ExecutionContext
import scala.util.Try

import com.mohiva.play.silhouette.api.Silhouette
import io.dataswift.models.hat.json.{ DataFeedItemJsonProtocol, RichDataJsonFormats }
import io.dataswift.models.hat._
import io.dataswift.models.hat.applications.Version
import org.hatdex.hat.api.service.applications.ApplicationsService
import org.hatdex.hat.authentication.{ ContainsApplicationRole, HatApiAuthEnvironment, HatApiController, WithRole }
import org.hatdex.hat.she.models.FunctionConfigurationJsonProtocol
import org.hatdex.hat.she.service._
import play.api.libs.json.Json
import play.api.mvc._

class FeedGenerator @Inject() (
    components: ControllerComponents,
    silhouette: Silhouette[HatApiAuthEnvironment],
    feedGeneratorService: FeedGeneratorService
  )(implicit
    val ec: ExecutionContext,
    applicationsService: ApplicationsService)
    extends HatApiController(components, silhouette)
    with RichDataJsonFormats
    with FunctionConfigurationJsonProtocol
    with DataFeedItemJsonProtocol {

  def getFeed(
      endpoint: String,
      since: Option[Long],
      until: Option[Long]): Action[AnyContent] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner())).async { implicit request =>
      feedGeneratorService
        .getFeed(endpoint, since, until, appHandlesLocations)
        .map(items => Ok(Json.toJson(items)))
    }

  def fullFeed(
      since: Option[Long],
      until: Option[Long]): Action[AnyContent] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner())).async { implicit request =>
      feedGeneratorService
        .fullFeed(since, until, appHandlesLocations)
        .map(items => Ok(Json.toJson(items)))
    }

  private val locationCompatibleVersion = Version("1.2.2")
  private val agentAppVersion           = "^([\\w\\s]+)/([\\d\\.]+).*".r
  private def appHandlesLocations(
    )(implicit requestHeader: RequestHeader): Boolean =
    requestingAppVersion().forall(app => app._1 != "HAT" || app._2 >= locationCompatibleVersion)

  private def requestingAppVersion(
    )(implicit requestHeader: RequestHeader): Option[(String, Version)] =
    requestHeader.headers.get("User-Agent").flatMap {
      _ match {
        case agentAppVersion(app, version) if app.startsWith("HAT Testing") =>
          Try(("HAT", Version(version))).toOption
        case agentAppVersion(app, version) =>
          Try((app, Version(version))).toOption
        case _ => None
      }
    }
}
