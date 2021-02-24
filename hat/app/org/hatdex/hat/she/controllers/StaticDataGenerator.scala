/*
 * Copyright (C) 2019 HAT Data Exchange Ltd
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
 * Written by Marios Tsekis <marios.tsekis@hatdex.org>
 * 2 / 2019
 */
package org.hatdex.hat.she.controllers

import javax.inject.Inject

import scala.concurrent.ExecutionContext

import com.mohiva.play.silhouette.api.Silhouette
import io.dataswift.models.hat.json.RichDataJsonFormats
import io.dataswift.models.hat.Owner
import org.hatdex.hat.api.service.applications.ApplicationsService
import org.hatdex.hat.authentication.{ ContainsApplicationRole, HatApiAuthEnvironment, HatApiController, WithRole }
import org.hatdex.hat.she.models.FunctionConfigurationJsonProtocol
import org.hatdex.hat.she.service.StaticDataGeneratorService
import play.api.libs.json.Json
import play.api.mvc._

class StaticDataGenerator @Inject() (
    components: ControllerComponents,
    silhouette: Silhouette[HatApiAuthEnvironment],
    feedGeneratorService: StaticDataGeneratorService
  )(implicit
    val ec: ExecutionContext,
    applicationsService: ApplicationsService)
    extends HatApiController(components, silhouette)
    with RichDataJsonFormats
    with FunctionConfigurationJsonProtocol {

  def getStaticData(endpoint: String): Action[AnyContent] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner())).async { implicit request =>
      feedGeneratorService
        .getStaticData(endpoint)
        .map(items => Ok(Json.toJson(items)))
    }
}
