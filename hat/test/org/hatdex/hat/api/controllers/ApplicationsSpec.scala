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

package org.hatdex.hat.api.controllers

import com.mohiva.play.silhouette.test._
import org.hatdex.hat.api.service.applications.ApplicationsServiceContext
import org.hatdex.hat.api.json.ApplicationJsonProtocol
import org.hatdex.hat.api.models.applications.{ Application, HatApplication }
import org.hatdex.hat.api.models.{ AccessToken, ErrorMessage }
import org.hatdex.hat.authentication.HatApiAuthEnvironment
import play.api.libs.json.{ JsObject, JsString }
import play.api.Logger
import play.api.test.{ FakeRequest }

import scala.concurrent.Await
import scala.concurrent.duration._
import io.dataswift.test.common.BaseSpec
import org.scalatest.{ BeforeAndAfter, BeforeAndAfterAll }
import play.api.test.Helpers
import play.api.test.Helpers._

class ApplicationsSpec extends BaseSpec with BeforeAndAfter with BeforeAndAfterAll with ApplicationsServiceContext {

  val logger = Logger(this.getClass)

  override def beforeAll() =
    Await.result(databaseReady, 60.seconds)

  override def before() = {
    import org.hatdex.hat.dal.Tables
    import org.hatdex.libs.dal.HATPostgresProfile.api._
    val action = DBIO.seq(Tables.ApplicationStatus.delete)
    Await.result(db.run(action), 60.seconds)
  }

  override def afterAll() =
    container.stop()

  import ApplicationJsonProtocol._
  import org.hatdex.hat.api.json.HatJsonFormats.{ accessTokenFormat, errorMessage }

  "The `applications` method" should "Return list of available applications" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.applications().apply(request)

    Helpers.status(result) must equal(OK)
    contentAsJson(result).validate[Seq[HatApplication]].isSuccess must equal(true)
    val apps = contentAsJson(result).as[Seq[HatApplication]]
    apps.length must equal(8)
    apps.find(_.application.id == notablesApp.id) === Some
    apps.find(_.application.id == notablesAppDebitless.id) === Some
    apps.find(_.application.id == notablesAppIncompatible.id) === Some
  }

  "The `applicationStatus` method" should "Return status of a single application" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.applicationStatus(notablesApp.id).apply(request)

    Helpers.status(result) must equal(OK)
    val app = contentAsJson(result).as[HatApplication]
    app.application.info.name must equal(notablesApp.info.name)
  }

  it should "Return 404 for a non-existent application" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.applicationStatus("random-id").apply(request)

    Helpers.status(result) must equal(NOT_FOUND)
    val error = contentAsJson(result).as[ErrorMessage]
    error.message must equal("Application not Found")
  }

  "The `hmi` method" should "Return the information about the specified application" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.hmi(notablesApp.id).apply(request)

    Helpers.status(result) must equal(OK)
    val app = contentAsJson(result).as[Application]
    app.id must equal(notablesApp.id)
  }

  it should "Return 404 for non-existend application hmi" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.hmi("random-id").apply(request)

    Helpers.status(result) must equal(NOT_FOUND)
    val error = contentAsJson(result).as[ErrorMessage]
    error.cause must startWith("Application configuration for ID random-id could not be found")
  }

  // problem
  "The `applicationSetup` method" should "Return setup application status" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.applicationSetup(notablesApp.id).apply(request)

    Helpers.status(result) must equal(OK)
    val app = contentAsJson(result).as[HatApplication]
    app.application.info.name must equal(notablesApp.info.name)
    app.setup must equal(true)
    app.active must equal(true)
  }

  it should "Return 404 for a non-existent application" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.applicationSetup("random-id").apply(request)

    Helpers.status(result) must equal(BAD_REQUEST)
    val error = contentAsJson(result).as[ErrorMessage]
    error.message must equal("Application not Found")
  }

  "The `applicationSetup` method" should "Return disabled application status" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.applicationDisable(notablesApp.id).apply(request)

    Helpers.status(result) must equal(OK)
    val app = contentAsJson(result).as[HatApplication]
    app.application.info.name must equal(notablesApp.info.name)
    app.setup must equal(true)
    app.active must equal(false)
  }

  it should "ApplicationDisable Return 404 for a non-existent application" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.applicationDisable("random-id").apply(request)

    Helpers.status(result) must equal(BAD_REQUEST)
    val error = contentAsJson(result).as[ErrorMessage]
    error.message must equal("Application not Found")
  }

  "The `applicationToken` method" should "Return 401 Forbidden for application token with no explicit permission" in {
    val authenticator: HatApiAuthEnvironment#A =
      FakeAuthenticator[HatApiAuthEnvironment](owner.loginInfo)
        .copy(customClaims =
          Some(
            JsObject(
              Map(
                "application" -> JsString("notables"),
                "applicationVersion" -> JsString("1.0.0")
              )
            )
          )
        )

    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator[HatApiAuthEnvironment](authenticator)(environment)

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.applicationToken(notablesApp.id).apply(request)

    Helpers.status(result) must equal(FORBIDDEN)
    logger.info(s"Got back result ${contentAsString(result)}")
    val error = contentAsJson(result) \ "error"
    error.get.as[String] must equal("Forbidden")
  }

  it should "Return 404 for application that does not exist" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.applicationToken("random-id").apply(request)

    Helpers.status(result) must equal(NOT_FOUND)
    val error = contentAsJson(result).as[ErrorMessage]
    error.message must equal("Application not Found")
  }

  it should "Return access token" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.applicationToken(notablesApp.id).apply(request)

    Helpers.status(result) must equal(OK)
    val token = contentAsJson(result).as[AccessToken]
    token.accessToken must not be empty
  }
}
