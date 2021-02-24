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
 * 7 / 2018
 */

package org.hatdex.hat.api.controllers

import javax.inject.Inject

import scala.concurrent.Future

import com.mohiva.play.silhouette.api.Silhouette
import io.dataswift.models.hat.json.ApplicationJsonProtocol
import io.dataswift.models.hat.applications.HatApplication
import io.dataswift.models.hat.{ ApplicationManage, ErrorMessage, Owner }
import org.hatdex.hat.api.service.RemoteExecutionContext
import org.hatdex.hat.api.service.applications.ApplicationsService
import org.hatdex.hat.authentication.{ ContainsApplicationRole, HatApiAuthEnvironment, HatApiController, WithRole }
import play.api.Logger
import play.api.http.HttpEntity
import play.api.libs.json.Json
import play.api.libs.ws.WSClient
import play.api.mvc.{ Action, AnyContent, ControllerComponents }

class ApplicationRequestProxy @Inject() (
    components: ControllerComponents,
    silhouette: Silhouette[HatApiAuthEnvironment],
    wsClient: WSClient
  )(implicit
    val ec: RemoteExecutionContext,
    applicationsService: ApplicationsService)
    extends HatApiController(components, silhouette)
    with ApplicationJsonProtocol {

  import io.dataswift.models.hat.json.HatJsonFormats.errorMessage

  val logger = Logger(this.getClass)

  def proxyRequest(
      id: String,
      path: String,
      method: String = "GET"): Action[AnyContent] =
    SecuredAction(
      ContainsApplicationRole(Owner(), ApplicationManage(id)) || WithRole(
          Owner()
        )
    ).async { implicit request =>
      logger.info(
        s"Proxy $method request for $id to $path with parameters: ${request.queryString}"
      )
      applicationsService.applicationStatus(id).flatMap { maybeStatus =>
        maybeStatus map {
          case HatApplication(app, _, true, _, _, _, _) =>
            applicationsService
              .applicationToken(request.identity, app)
              .flatMap { token =>
                val baseRequest = wsClient
                  .url(s"${app.kind.url}/$path")
                  .withHttpHeaders("x-auth-token" -> token.accessToken)
                  .addQueryStringParameters(
                    request.queryString.map(p => (p._1, p._2.head)).toSeq: _*
                  )
                  .withMethod(method)

                request.body.asJson
                  .fold(baseRequest)(b => baseRequest.withBody(b))
                  .stream()
                  .map(r =>
                    new Status(r.status).sendEntity(
                      HttpEntity
                        .Strict(r.bodyAsBytes, Some("application/json"))
                    )
                  )
              }

          case _ =>
            Future.successful(
              BadRequest(
                Json.toJson(
                  ErrorMessage(
                    "Application not active",
                    s"Application $id does not appear to be activated by the user"
                  )
                )
              )
            )
        } getOrElse {
          Future.successful(
            NotFound(
              Json.toJson(
                ErrorMessage(
                  "Application not Found",
                  s"Application $id does not appear to be a valid application registered with the DEX"
                )
              )
            )
          )
        }
      }
    }
}
