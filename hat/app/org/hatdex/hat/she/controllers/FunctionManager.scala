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

import scala.concurrent.{ ExecutionContext, Future }

import com.mohiva.play.silhouette.api.Silhouette
import com.mohiva.play.silhouette.api.actions.SecuredRequest
import io.dataswift.models.hat.json.RichDataJsonFormats
import io.dataswift.models.hat._
import org.hatdex.hat.api.service.applications.ApplicationsService
import org.hatdex.hat.authentication.{ ContainsApplicationRole, HatApiAuthEnvironment, HatApiController, WithRole }
import org.hatdex.hat.she.models.{ FunctionConfiguration, FunctionConfigurationJsonProtocol, FunctionStatus }
import org.hatdex.hat.she.service.{ FunctionExecutionTriggerHandler, FunctionService }
import play.api.Logger
import play.api.libs.json._
import play.api.mvc._

class FunctionManager @Inject() (
    components: ControllerComponents,
    silhouette: Silhouette[HatApiAuthEnvironment],
    functionService: FunctionService,
    functionExecutionDispatcher: FunctionExecutionTriggerHandler
  )(implicit
    val ec: ExecutionContext,
    applicationsService: ApplicationsService)
    extends HatApiController(components, silhouette)
    with RichDataJsonFormats
    with FunctionConfigurationJsonProtocol {

  private val logger = Logger(this.getClass)

  def functionList(): Action[AnyContent] =
    SecuredAction(
      ContainsApplicationRole(Owner()) || WithRole(Owner(), Platform())
    ).async { implicit request =>
      functionService.all(active = false).map { functions =>
        Ok(Json.toJson(functions))
      }
    }

  def functionGet(function: String): Action[AnyContent] =
    SecuredAction(
      ContainsApplicationRole(Owner()) || WithRole(Owner(), Platform())
    ).async { implicit request =>
      logger.debug(s"Get function $function")
      functionService.get(id = function).map { maybeFunction =>
        maybeFunction.map { function =>
          Ok(Json.toJson(function))
        } getOrElse {
          NotFound(
            Json.toJson(
              ErrorMessage(
                "Function Not Found",
                s"Function $function not found"
              )
            )
          )
        }
      }
    }

  def functionEnable(function: String): Action[AnyContent] =
    SecuredAction(ContainsApplicationRole(Owner()) || WithRole(Owner())).async { implicit request =>
      functionSetEnabled(function, enabled = true)
    }

  def functionDisable(function: String): Action[AnyContent] =
    SecuredAction(ContainsApplicationRole(Owner()) || WithRole(Owner())).async { implicit request =>
      functionSetEnabled(function, enabled = false)
    }

  protected def functionSetEnabled(
      function: String,
      enabled: Boolean
    )(implicit request: SecuredRequest[HatApiAuthEnvironment, AnyContent]): Future[Result] = {
    logger.debug(s"Enable function $function = $enabled")
    functionService.get(function).flatMap { maybeFunction =>
      maybeFunction.map { function =>
        functionService
          .save(function.copy(status = function.status.copy(enabled = enabled)))
          .map(f => Ok(Json.toJson(f)))
      } getOrElse {
        Future.successful(
          NotFound(
            Json.toJson(
              ErrorMessage(
                "Function Not Found",
                s"Function $function not found"
              )
            )
          )
        )
      }
    }
  }

  // TODO: ApplicationManage permission being used to authorise function trigger. Consider updating to tool-specific permissions
  def functionTrigger(
      function: String,
      useAll: Boolean): Action[AnyContent] =
    SecuredAction(
      ContainsApplicationRole(Owner(), ApplicationManage(function)) || WithRole(
          Owner(),
          Platform()
        )
    ).async { implicit request =>
      logger.debug(s"Trigger function $function")
      functionService.get(function).flatMap { maybeFunction =>
        maybeFunction.map {
          case c: FunctionConfiguration if c.status.available && c.status.enabled =>
            functionExecutionDispatcher
              .trigger(request.dynamicEnvironment.domain, c, useAll)(ec)
              .map(_ => Ok(Json.toJson(SuccessResponse("Function Executed"))))
              .recover {
                case e =>
                  logger.error(
                    s"Function $function execution errored with ${e.getMessage}",
                    e
                  )
                  InternalServerError(
                    Json.toJson(
                      ErrorMessage(
                        "Function Execution Failed",
                        s"Function $function execution errored with ${e.getMessage}"
                      )
                    )
                  )
              }
          case FunctionConfiguration(
                _,
                _,
                _,
                _,
                _,
                FunctionStatus(false, _, _, _)
              ) =>
            Future.successful(
              BadRequest(
                Json.toJson(
                  ErrorMessage(
                    "Function Not Available",
                    s"Function $function not available for execution"
                  )
                )
              )
            )
          case FunctionConfiguration(
                _,
                _,
                _,
                _,
                _,
                FunctionStatus(true, false, _, _)
              ) =>
            Future.successful(
              BadRequest(
                Json.toJson(
                  ErrorMessage(
                    "Function Not Enabled",
                    s"Function $function not enabled for execution"
                  )
                )
              )
            )
        } getOrElse {
          Future.successful(
            NotFound(
              Json.toJson(
                ErrorMessage(
                  "Function Not Found",
                  s"Function $function not found"
                )
              )
            )
          )
        }
      }
    }
}
