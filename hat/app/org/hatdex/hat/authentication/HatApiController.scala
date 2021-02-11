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

package org.hatdex.hat.authentication

import javax.inject.Inject
import com.digitaltangible.playguard.{ RateLimitActionFilter, RateLimiter }
import com.mohiva.play.silhouette.api.actions._
import com.mohiva.play.silhouette.api.{ Environment, Silhouette }
import org.hatdex.hat.api.json.HatJsonFormats
import org.hatdex.hat.api.models.applications.HatApplication
import org.hatdex.hat.api.models.{ ErrorMessage, User }
import org.hatdex.hat.api.service.applications.ApplicationsService
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.resourceManagement._
import org.hatdex.libs.dal.HATPostgresProfile.api.Database
import play.api.Configuration
import play.api.i18n.I18nSupport
import play.api.libs.json.{ Format, Json }
import play.api.mvc._

import scala.concurrent.{ ExecutionContext, Future }

abstract class HatController[T <: HatAuthEnvironment](
    components: ControllerComponents,
    silhouette: Silhouette[T])
    extends AbstractController(components)
    with I18nSupport {

  def env: Environment[T] = silhouette.env
  def SecuredAction: SecuredActionBuilder[T, AnyContent] =
    silhouette.securedAction(env)
  def UnsecuredAction: UnsecuredActionBuilder[T, AnyContent] =
    silhouette.unsecuredAction(env)
  def UserAwareAction: UserAwareActionBuilder[T, AnyContent] =
    silhouette.userAwareAction(env)

  implicit def securedRequest2User[A](
      implicit request: SecuredRequest[T, A]): HatUser = request.identity
  implicit def userAwareRequest2UserOpt[A](
      implicit request: UserAwareRequest[T, A]): Option[HatUser] = request.identity
  implicit def securedRequest2HatServer[A](
      implicit request: SecuredRequest[T, A]): HatServer = request.dynamicEnvironment
  implicit def userAwareRequest2HatServer[A](
      implicit request: UserAwareRequest[T, A]): HatServer = request.dynamicEnvironment
  implicit def securedRequest2Authenticator[A](
      implicit request: SecuredRequest[T, A]): T#A = request.authenticator
  implicit def hatServer2db(implicit hatServer: HatServer): Database =
    hatServer.db
  implicit def identity2ApiUser(implicit identity: T#I): User =
    ModelTranslation.fromInternalModel(identity)

  def request2ApplicationStatus(
      request: SecuredRequest[HatApiAuthEnvironment, _]
    )(implicit applicationsService: ApplicationsService): Future[Option[HatApplication]] =
    request.authenticator.customClaims.flatMap { customClaims =>
      (customClaims \ "application").asOpt[String]
    } map { app =>
      applicationsService.applicationStatus(app)(
        request.dynamicEnvironment,
        request.identity,
        request
      )
    } getOrElse {
      Future.successful(None)
    }

  def request2ApplicationStatus(
      request: UserAwareRequest[HatApiAuthEnvironment, _]
    )(implicit applicationsService: ApplicationsService): Future[Option[HatApplication]] =
    (request.authenticator, request.identity) match {
      case (Some(authenticator), Some(identity)) =>
        authenticator.customClaims.flatMap { customClaims =>
          (customClaims \ "application").asOpt[String]
        } map { app =>
          applicationsService.applicationStatus(app)(
            request.dynamicEnvironment,
            identity,
            request
          )
        } getOrElse {
          Future.successful(None)
        }
      case _ =>
        Future.successful(None) // if no authenticator, certainly no application
    }
}

abstract class HatApiController(
    components: ControllerComponents,
    silhouette: Silhouette[HatApiAuthEnvironment])
    extends HatController[HatApiAuthEnvironment](components, silhouette)

/**
  * A Limiter for user logic.
  */
class UserLimiter @Inject() (
    implicit
    configuration: Configuration,
    ec: ExecutionContext) {
  import scala.language.higherKinds

  /**
    * A Rate limiter Function for.
    *
    * @param rateLimiter The rate limiter implementation.
    * @param reject The function to apply on reject.
    * @param requestKeyExtractor The Request Parameter we want to filter from.
    * @tparam K the key by which to identify the user.
    */
  def createUserAware[T <: HatAuthEnvironment, R[_] <: UserAwareRequest[T, _], K](
      rateLimiter: RateLimiter
    )(reject: R[_] => Result,
      requestKeyExtractor: R[_] => K): RateLimitActionFilter[R] with ActionFunction[R, R] =
    new RateLimitActionFilter[R](rateLimiter)(reject, requestKeyExtractor) with ActionFunction[R, R]

  def createSecured[T <: HatAuthEnvironment, R[_] <: SecuredRequest[T, _], K](
      rateLimiter: RateLimiter
    )(reject: R[_] => Result,
      requestKeyExtractor: R[_] => K): RateLimitActionFilter[R] with ActionFunction[R, R] =
    new RateLimitActionFilter[R](rateLimiter)(reject, requestKeyExtractor) with ActionFunction[R, R]

  type Secured[B]   = SecuredRequest[HatApiAuthEnvironment, B]
  type UserAware[B] = UserAwareRequest[HatApiAuthEnvironment, B]

  // allow 10 requests immediately and get a new token every 2 seconds
  private val rl = new RateLimiter(10, 1f / 2, "[Rate Limiter]")

  implicit private val errorMesageFormat: Format[ErrorMessage] =
    HatJsonFormats.errorMessage
  private def response(r: RequestHeader) =
    Results.BadRequest(
      Json.toJson(
        ErrorMessage(
          "Request rate exceeded",
          "Rate of requests from your IP exceeded",
          Some(Seq(s"Request to ${r.path}"))
        )
      )
    )

  def UserAwareRateLimit: RateLimitActionFilter[UserAware] with ActionFunction[UserAware, UserAware] =
    createUserAware[HatApiAuthEnvironment, UserAware, String](rl)(
      response,
      clientIp
    )

  def SecureRateLimit: RateLimitActionFilter[Secured] with ActionFunction[Secured, Secured] =
    createSecured[HatApiAuthEnvironment, Secured, String](rl)(
      response,
      clientIp
    )

  def clientIp(request: RequestHeader)(implicit conf: Configuration): String =
    (for {
      configuredHeader <- conf.get[Option[String]]("playguard.clientipheader")
      ip <- request.headers.get(configuredHeader)
    } yield ip) getOrElse {

      // Consider X-Forwarded-For as most accurate if it exists
      // Since it is easy to forge an X-Forwarded-For, only consider the last ip added by our proxy as the most accurate
      // https://en.wikipedia.org/wiki/X-Forwarded-For
      request.headers
        .get("X-Forwarded-For")
        .map(_.split(",").last.trim)
        .getOrElse {
          request.remoteAddress
        }

    }
}
