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
 * 5 / 2017
 */
package org.hatdex.hat.api.service

import javax.inject.Inject

import scala.concurrent.Future

import akka.http.scaladsl.model.Uri
import com.mohiva.play.silhouette.api.Silhouette
import io.dataswift.models.hat._
import org.hatdex.hat.authentication.HatApiAuthEnvironment
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.dal.Tables._
import org.hatdex.hat.resourceManagement.HatServer
import org.hatdex.libs.dal.HATPostgresProfile.api._
import org.joda.time.LocalDateTime
import play.api.Logger
import play.api.libs.json.{ JsObject, Json }
import play.api.mvc.RequestHeader

class HatServicesService @Inject() (
    silhouette: Silhouette[HatApiAuthEnvironment]
  )(implicit val ec: DalExecutionContext) {
  private val logger = Logger(this.getClass)

  def hatServices(
      categories: Set[String]
    )(implicit hatServer: HatServer): Future[Seq[HatService]] = {
    val applicationsQuery = for {
      application <- Applications.filter(_.category inSet categories)
    } yield application

    val eventualDbApps = hatServer.db.run(applicationsQuery.result)
    eventualDbApps map { dbApps =>
      dbApps.map(applicationFromDbModel)
    }
  }

  def save(
      service: HatService
    )(implicit hatServer: HatServer): Future[HatService] = {
    val app = ApplicationsRow(
      LocalDateTime.now(),
      None,
      service.title,
      service.description,
      service.logoUrl,
      service.url,
      service.authUrl,
      service.browser,
      service.category,
      service.setup,
      service.loginAvailable,
      service.namespace
    )

    hatServer.db.run(Applications.insertOrUpdate(app)).map(_ => service)
  }

  private def applicationFromDbModel(app: ApplicationsRow): HatService =
    HatService(
      app.title,
      app.namespace,
      app.description,
      app.logoUrl,
      app.url,
      app.authUrl,
      app.browser,
      app.category,
      app.setup,
      app.loginAvailable
    )

  def findOrCreateHatService(
      name: String,
      redirectUrl: String
    )(implicit hatServer: HatServer): Future[HatService] = {
    val redirectUri = Uri(redirectUrl)

    hatServices(Set("app", "dataplug", "testapp")) map { approvedHatServices =>
      approvedHatServices
        .find(s => s.title == name && redirectUrl.startsWith(s.url))
        .map(
          _.copy(
            url = s"${redirectUri.scheme}://${redirectUri.authority.toString}",
            authUrl = redirectUri.path.toString()
          )
        )
        .getOrElse(
          HatService(
            name,
            name.toLowerCase,
            redirectUrl,
            "/assets/images/haticon.png",
            redirectUrl,
            redirectUri.path.toString(),
            browser = false,
            category = "app",
            setup = true,
            loginAvailable = true
          )
        )
    }
  }

  def generateUserTokenClaims(
      user: HatUser,
      service: HatService
    )(implicit hatServer: HatServer): JsObject = {
    val accessScope =
      if (service.browser) user.primaryRole.title
      else "validate"
    val resource =
      if (service.browser) hatServer.domain
      else service.url

    JsObject(
      Map(
        "resource" -> Json.toJson(resource),
        "accessScope" -> Json.toJson(accessScope)
      )
    )
  }

  def hatServiceToken(
      user: HatUser,
      service: HatService
    )(implicit hatServer: HatServer,
      requestHeader: RequestHeader): Future[AccessToken] = {
    val customClaims = generateUserTokenClaims(user, service)

    silhouette.env.authenticatorService
      .create(user.loginInfo)
      .map(_.copy(customClaims = Some(customClaims)))
      .flatMap(silhouette.env.authenticatorService.init)
      .map(AccessToken(_, user.userId))
  }

  def hatServiceLink(
      user: HatUser,
      service: HatService,
      maybeRedirect: Option[String] = None
    )(implicit hatServer: HatServer,
      requestHeader: RequestHeader): Future[HatService] = {
    logger.debug(
      s"Generating link for service $service, redirect $maybeRedirect"
    )
    val eventualUri =
      if (service.loginAvailable)
        hatServiceToken(user, service) map { token =>
          val query = maybeRedirect map { redirect =>
            val originalQuery: Map[String, String] =
              Uri(redirect).query().toMap + ("token" -> token.accessToken)
            logger.debug(s"Got redirect url: ${Uri(redirect)} ${originalQuery}")
            Uri.Query(originalQuery)
          } getOrElse {
            Uri.Query("token" -> token.accessToken)
          }

          maybeRedirect
            .map(Uri(_))
            .getOrElse(Uri(service.url).withPath(Uri.Path(service.authUrl)))
            .withQuery(query)
        }
      else
        Future.successful(Uri(service.url).withPath(Uri.Path(service.authUrl)))

    eventualUri map { serviceLink =>
      service.copy(url = serviceLink.toString, authUrl = "")
    }
  }

}
