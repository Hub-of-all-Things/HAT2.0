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
 * 8 / 2017
 */

package org.hatdex.hat.api.controllers

import javax.inject.Inject

import scala.concurrent.ExecutionContext

import com.mohiva.play.silhouette.api.Silhouette
import io.dataswift.models.hat.json.RichDataJsonFormats
import io.dataswift.models.hat._
import org.hatdex.hat.api.service.MigrationService
import org.hatdex.hat.authentication.{ HatApiAuthEnvironment, HatApiController, WithRole }
import play.api.Logger
import play.api.libs.json._
import play.api.mvc._

class DataMigration @Inject() (
    components: ControllerComponents,
    silhouette: Silhouette[HatApiAuthEnvironment],
    migrationService: MigrationService
  )(implicit
    val ec: ExecutionContext)
    extends HatApiController(components, silhouette)
    with RichDataJsonFormats {

  private val logger = Logger(this.getClass)

  def migrateData(
      fromSource: String,
      fromTableName: String,
      toNamespace: String,
      toEndpoint: String,
      includeTimestamp: Boolean): Action[AnyContent] =
    SecuredAction(WithRole(Owner())).async { implicit request =>
      logger.info(
        s"Migrate data from $fromSource:$fromTableName to $toNamespace/$toEndpoint"
      )
      val eventualCount = migrationService.migrateOldData(
        request.identity.userId,
        s"$toNamespace/$toEndpoint",
        fromTableName,
        fromSource,
        None,
        None,
        includeTimestamp
      )

      eventualCount map { count =>
        Ok(Json.toJson(SuccessResponse(s"Migrated $count records")))
      }
    }

}
