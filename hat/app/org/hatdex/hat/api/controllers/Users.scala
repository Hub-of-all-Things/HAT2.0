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

package org.hatdex.hat.api.controllers

import java.util.UUID
import javax.inject.Inject

import scala.concurrent.{ ExecutionContext, Future }

import com.mohiva.play.silhouette.api.Silhouette
import io.dataswift.models.hat.json.HatJsonFormats
import io.dataswift.models.hat.{ Owner, Platform, _ }
import org.hatdex.hat.api.service.UsersService
import org.hatdex.hat.api.service.applications.ApplicationsService
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.authentication.{ HatApiController, WithRole, _ }
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.utils.HatBodyParsers
import play.api.Logger
import play.api.libs.json.Json
import play.api.mvc._

class Users @Inject() (
    components: ControllerComponents,
    silhouette: Silhouette[HatApiAuthEnvironment],
    usersService: UsersService,
    hatBodyParsers: HatBodyParsers,
    implicit val ec: ExecutionContext,
    implicit val applicationsService: ApplicationsService)
    extends HatApiController(components, silhouette)
    with HatJsonFormats {

  private val logger = Logger(this.getClass)

  def listUsers(): Action[AnyContent] =
    SecuredAction.async { implicit request =>
      usersService.listUsers map { users =>
        Ok(Json.toJson(users.map(ModelTranslation.fromInternalModel)))
      }
    }

  private def privilegedRole(user: HatUser): Boolean = {
    val privileged = Seq(Platform(), Owner())
    if (user.roles.intersect(privileged).nonEmpty)
      true
    else
      false
  }

  def createUser(): Action[User] =
    SecuredAction(
      WithRole(Owner(), Platform()) || ContainsApplicationRole(
          Owner(),
          Platform()
        )
    ).async(hatBodyParsers.json[User]) { implicit request =>
      val user = request.body
      logger.debug(s"Creating user $user")
      val hatUser = ModelTranslation.fromExternalModel(user, enabled = true)
      if (privilegedRole(hatUser))
        Future.successful(
          BadRequest(
            Json.toJson(
              ErrorMessage(
                "Invalid User",
                s"Users with privileged roles may not be created"
              )
            )
          )
        )
      else
        usersService.getUser(user.email).flatMap { maybeExistingUser =>
          maybeExistingUser map { _ =>
            Future.successful(
              BadRequest(
                Json.toJson(
                  ErrorMessage(
                    "Error creating user",
                    s"User ${user.email} already exists"
                  )
                )
              )
            )
          } getOrElse {
            usersService.saveUser(hatUser).map { created =>
              Created(Json.toJson(ModelTranslation.fromInternalModel(created)))
            } recover {
              case e =>
                BadRequest(
                  Json.toJson(
                    ErrorMessage(
                      "Error creating user",
                      s"User not created: ${e.getMessage}"
                    )
                  )
                )
            }
          }
        }
    }

  def deleteUser(userId: UUID): Action[AnyContent] =
    SecuredAction(
      WithRole(Owner(), Platform()) || ContainsApplicationRole(
          Owner(),
          Platform()
        )
    ).async { implicit request =>
      usersService.getUser(userId) flatMap { maybeUser =>
        maybeUser map { user =>
          if (privilegedRole(user))
            Future.successful(
              Forbidden(
                Json.toJson(
                  ErrorMessage(
                    "Forbidden",
                    s"Privileged account can not be enabled or disabled"
                  )
                )
              )
            )
          else
            usersService.deleteUser(userId) map { _ =>
              Ok(Json.toJson(SuccessResponse(s"Account deleted")))
            }
        } getOrElse {
          Future.successful(
            NotFound(
              Json.toJson(
                ErrorMessage("No such User", s"User $userId does not exist")
              )
            )
          )
        }
      }
    }

  def updateUser(userId: UUID): Action[User] =
    SecuredAction(
      WithRole(Owner(), Platform()) || ContainsApplicationRole(
          Owner(),
          Platform()
        )
    ).async(hatBodyParsers.json[User]) { implicit request =>
      usersService.getUser(userId) flatMap { maybeUser =>
        maybeUser.filter(_.userId == request.body.userId) map { user =>
          val updatedUser =
            ModelTranslation.fromExternalModel(request.body, enabled = true)
          if (privilegedRole(user) || privilegedRole(updatedUser))
            Future.successful(
              Forbidden(
                Json.toJson(
                  ErrorMessage(
                    "Forbidden",
                    s"Privileged account can not be enabled or disabled"
                  )
                )
              )
            )
          else
            usersService.saveUser(updatedUser) map { created =>
              Created(Json.toJson(ModelTranslation.fromInternalModel(created)))
            }
        } getOrElse {
          Future.successful(
            NotFound(
              Json.toJson(
                ErrorMessage("No such User", s"User $userId does not exist")
              )
            )
          )
        }
      }
    }

  def enableUser(userId: UUID): Action[AnyContent] =
    SecuredAction(
      WithRole(Owner(), Platform()) || ContainsApplicationRole(
          Owner(),
          Platform()
        )
    ).async { implicit request =>
      usersService.getUser(userId) flatMap { maybeUser =>
        maybeUser map { user =>
          if (privilegedRole(user))
            Future.successful(
              Forbidden(
                Json.toJson(
                  ErrorMessage(
                    "Forbidden",
                    s"Privileged account can not be enabled or disabled"
                  )
                )
              )
            )
          else
            usersService.changeUserState(userId, enabled = true).map { _ =>
              Ok(Json.toJson(SuccessResponse("Enabled")))
            }
        } getOrElse {
          Future.successful(
            NotFound(
              Json.toJson(
                ErrorMessage("No such User", s"User $userId does not exist")
              )
            )
          )
        }
      }
    }

  def disableUser(userId: UUID): Action[AnyContent] =
    SecuredAction(
      WithRole(Owner(), Platform()) || ContainsApplicationRole(
          Owner(),
          Platform()
        )
    ).async { implicit request =>
      usersService.getUser(userId) flatMap { maybeUser =>
        maybeUser map { user =>
          if (privilegedRole(user))
            Future.successful(
              Forbidden(
                Json.toJson(
                  ErrorMessage(
                    "Forbidden",
                    s"Privileged account can not be enabled or disabled"
                  )
                )
              )
            )
          else
            usersService.changeUserState(userId, enabled = true).map { _ =>
              Ok(Json.toJson(SuccessResponse("Enabled")))
            }
        } getOrElse {
          Future.successful(
            NotFound(
              Json.toJson(
                ErrorMessage("No such User", s"User $userId does not exist")
              )
            )
          )
        }
      }
    }

}
