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
 * 3 / 2017
 */

package org.hatdex.hat.api.controllers

import com.mohiva.play.silhouette.test._
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.phata.models.{ ApiPasswordChange, ApiPasswordResetRequest, ApiValidationRequest, MailTokenUser }
import org.hatdex.hat.resourceManagement.HatServer
import play.api.Logger
import org.scalatest._
import matchers.should._
import flatspec._
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.{ Logger, Application => PlayApplication }
import play.api.test.Helpers._
import play.api.test.FakeRequest
import org.hatdex.hat.api.models.{ Owner, Platform => DSPlatform }
import akka.stream.Materializer
import com.atlassian.jwt.core.keys.KeyUtils
import scala.concurrent.{ Await }
import scala.concurrent.duration._
import org.hatdex.hat.authentication.models.HatUser
import play.api.Configuration
import java.io.StringReader
import com.dimafeng.testcontainers.{ ForAllTestContainer, PostgreSQLContainer }
import org.hatdex.hat.helpers.{ ContainerUtils }
import org.hatdex.libs.dal.HATPostgresProfile.backend.Database
import com.mohiva.play.silhouette.api.Environment
import com.mohiva.play.silhouette.test._
import org.hatdex.hat.authentication.HatApiAuthEnvironment
import play.api.test.Helpers
import play.api.test.{ FakeRequest }
import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, HatServer }

import scala.concurrent.duration._
import scala.concurrent.{ Await }
import play.DefaultApplication

class AuthenticationSpec
    extends AnyFlatSpec
    with Matchers
    with ContainerUtils
    with AuthenticationContext
    with ForAllTestContainer {

  import scala.concurrent.ExecutionContext.Implicits.global

  // Ephemeral PG Container for this test suite
  override val container = PostgreSQLContainer()
  container.start()

  val logger                = Logger(this.getClass)
  val hatAddress            = "hat.hubofallthings.net"
  val hatUrl                = s"https://$hatAddress"
  private val configuration = Configuration.from(FakeHatConfiguration.config)
  private val hatConfig     = configuration.get[Configuration](s"hat.$hatAddress")

  private val keyUtils = new KeyUtils()
  implicit val db: Database = Database.forURL(
    url = container.jdbcUrl,
    user = container.username,
    password = container.password
  )

  implicit lazy val materializer: Materializer = application.materializer

  val conf = containerToConfig(container)
  Await.result(databaseReady(db, conf), 60.seconds)

  implicit val hatServer: HatServer = HatServer(
    hatAddress,
    "hat",
    "user@hat.org",
    keyUtils.readRsaPrivateKeyFromPem(new StringReader(hatConfig.get[String]("privateKey"))),
    keyUtils.readRsaPublicKeyFromPem(new StringReader(hatConfig.get[String]("publicKey"))),
    db
  )

  val application: PlayApplication = new GuiceApplicationBuilder()
    .configure(FakeHatConfiguration.config)
    .build()

  val owner = new HatUser(userId = java.util.UUID.randomUUID(),
                          email = "user@hat.org",
                          pass = Some("$2a$06$QprGa33XAF7w8BjlnKYb3OfWNZOuTdzqKeEsF7BZUfbiTNemUW/n."),
                          name = "hat",
                          roles = Seq(Owner(), DSPlatform()),
                          enabled = true
  )

  implicit val env: Environment[HatApiAuthEnvironment] =
    FakeEnvironment[HatApiAuthEnvironment](Seq(owner.loginInfo -> owner), hatServer)

  "The `publicKey` method" should "Return public key of the HAT" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")

    val controller = application.injector.instanceOf[Authentication]
    val result     = Helpers.call(controller.publicKey(), request)

    status(result) should equal(OK)
    //contentAsString(result) must startWith("-----BEGIN PUBLIC KEY-----\n")
  }
  /*
  "The `validateToken` method" should {
    "return status 401 if authenticator but no identity was found" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withAuthenticator(LoginInfo("xing", "comedian@watchmen.com"))

      val controller = application.injector.instanceOf[Authentication]
      val result     = controller.validateToken().apply(request)

      status(result) must equalTo(UNAUTHORIZED)
    }

    "Return simple success message for a valid token" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)

      val controller = application.injector.instanceOf[Authentication]
      val result     = controller.validateToken().apply(request)

      status(result) must equalTo(OK)
      (contentAsJson(result) \ "message").as[String] must equalTo("Authenticated")
    }
  }

  "The `hatLogin` method" should {
    "return status 401 if authenticator but no identity was found" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withAuthenticator(LoginInfo("xing", "comedian@watchmen.com"))

      val controller             = application.injector.instanceOf[Authentication]
      val result: Future[Result] = controller.hatLogin("TestService", "http://testredirect").apply(request)

      status(result) must equalTo(UNAUTHORIZED)
    }

    "return status 403 if authenticator and existing identity but wrong role" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(dataDebitUser.loginInfo)

      val controller             = application.injector.instanceOf[Authentication]
      val result: Future[Result] = controller.hatLogin("TestService", "http://testredirect").apply(request)

      status(result) must equalTo(FORBIDDEN)
    }

    "return redirect url for authenticated owner" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)

      val controller             = application.injector.instanceOf[Authentication]
      val result: Future[Result] = controller.hatLogin("TestService", "http://testredirect").apply(request)

      status(result) must equalTo(OK)
      contentAsString(result) must contain("testredirect")
      contentAsString(result) must contain("token=")
    }
  }

  "The `accessToken` method" should {
    "return status 401 if no credentials provided" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")

      val controller             = application.injector.instanceOf[Authentication]
      val result: Future[Result] = controller.accessToken().apply(request)

      status(result) must equalTo(UNAUTHORIZED)
    }

    "return status 401 if credentials but no matching identity" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withHeaders("username" -> "test", "password" -> "test")

      val controller = application.injector.instanceOf[Authentication]

      controller.accessToken().apply(request) must throwA[IdentityNotFoundException].await(1, 30.seconds)

    }

    "return Access Token for the authenticated user" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withHeaders("username" -> "hatuser", "password" -> "pa55w0rd")

      val controller = application.injector.instanceOf[Authentication]

      val encoder  = new Base64AuthenticatorEncoder()
      val settings = JWTRS256AuthenticatorSettings("X-Auth-Token", None, "hat.org", Some(3.days), 3.days)

      val result: Future[Result] = controller.accessToken().apply(request)

      status(result) must equalTo(OK)
      val token        = (contentAsJson(result) \ "accessToken").as[String]
      val unserialized = JWTRS256Authenticator.unserialize(token, encoder, settings)
      unserialized must beSuccessfulTry
      unserialized.get.loginInfo must be equalTo owner.loginInfo
    }
  }

  "The `passwordChangeProcess` method should" in {
    "return status 403 if not owner" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(dataDebitUser.loginInfo)
        .withJsonBody(Json.toJson(passwordChangeIncorrect))

      val controller             = application.injector.instanceOf[Authentication]
      val result: Future[Result] = Helpers.call(controller.passwordChangeProcess(), request)

      status(result) must equalTo(FORBIDDEN)
    }

    "return status 403 if old password incorrect" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)
        .withJsonBody(Json.toJson(passwordChangeIncorrect))

      val controller             = application.injector.instanceOf[Authentication]
      val result: Future[Result] = Helpers.call(controller.passwordChangeProcess(), request)

      status(result) must equalTo(FORBIDDEN)
    }

    "return status 400 if new password too weak" in {
      val request = FakeRequest[JsValue](
        Helpers.POST,
        "/control/v2/auth/password",
        headers = FakeHeaders(Seq((HeaderNames.ACCEPT, MimeTypes.JSON), (HeaderNames.CONTENT_TYPE, MimeTypes.JSON))),
        body = Json.toJson(passwordChangeSimple),
        remoteAddress = "hat.hubofallthings.net"
      )
        .withAuthenticator(owner.loginInfo)

      val maybeResult: Option[Future[Result]] = Helpers.route(application, request)
      //      val controller = application.injector.instanceOf[Authentication]
      //      val result: Future[Result] = Helpers.call(controller.passwordChangeProcess(), request)
      maybeResult must beSome
      val result = maybeResult.get

      status(result) must equalTo(BAD_REQUEST)
      //      contentType(result) must beSome("application/json")
      (contentAsJson(result) \ "error").as[String] must equalTo("Bad Request")
    }

    "Change password if it is sufficiently strong" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)
        .withJsonBody(Json.toJson(passwordChangeStrong))

      val controller             = application.injector.instanceOf[Authentication]
      val result: Future[Result] = Helpers.call(controller.passwordChangeProcess(), request)

      status(result) must equalTo(OK)
      (contentAsJson(result) \ "message").as[String] must equalTo("Password changed")
    }
  }

  "The `handleForgotPassword` method should" in {
    "Hide the fact that email doesn't match by returning status 200" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(dataDebitUser.loginInfo)
        .withJsonBody(Json.toJson(passwordForgottenIncorrect))

      val controller             = application.injector.instanceOf[Authentication]
      val result: Future[Result] = Helpers.call(controller.handleForgotPassword, request)

      status(result) must equalTo(OK)
    }

    "Send email to the owner if provided email matches" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(dataDebitUser.loginInfo)
        .withJsonBody(Json.toJson(passwordForgottenOwner))

      val controller             = application.injector.instanceOf[Authentication]
      val result: Future[Result] = Helpers.call(controller.handleForgotPassword, request)

      status(result) must equalTo(OK)
      there was one(mockMailer).passwordReset(any[String], any[String])(any[MessagesApi], any[Lang], any[HatServer])
    }
  }

  "The `handleResetPassword` method should" in {
    "Return status 401 if no such token exists" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(dataDebitUser.loginInfo)
        .withJsonBody(Json.toJson(passwordResetStrong))

      val controller             = application.injector.instanceOf[Authentication]
      val result: Future[Result] = Helpers.call(controller.handleResetPassword("nosuchtoken"), request)

      status(result) must equalTo(UNAUTHORIZED)
      (contentAsJson(result) \ "cause").as[String] must equalTo("Token does not exist")
    }

    "Return status 401 if token has expired" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)
        .withJsonBody(Json.toJson(passwordResetStrong))

      val controller   = application.injector.instanceOf[Authentication]
      val tokenService = application.injector.instanceOf[MailTokenUserService]
      val tokenId      = UUID.randomUUID().toString

      val result: Future[Result] = for {
        _ <- tokenService.create(MailTokenUser(tokenId, "hat@hat.org", DateTime.now().minusHours(1), isSignUp = false))
        result <- Helpers.call(controller.handleResetPassword(tokenId), request)
      } yield result

      status(result) must equalTo(UNAUTHORIZED)
      (contentAsJson(result) \ "cause").as[String] must equalTo("Token expired or invalid")
    }

    "Return status 401 if token email doesn't match owner" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)
        .withJsonBody(Json.toJson(passwordResetStrong))

      val controller   = application.injector.instanceOf[Authentication]
      val tokenService = application.injector.instanceOf[MailTokenUserService]
      val tokenId      = UUID.randomUUID().toString

      val result: Future[Result] = for {
        _ <- tokenService.create(MailTokenUser(tokenId, "email@hat.org", DateTime.now().plusHours(1), isSignUp = false))
        result <- Helpers.call(controller.handleResetPassword(tokenId), request)
      } yield result

      status(result) must equalTo(UNAUTHORIZED)
      (contentAsJson(result) \ "cause").as[String] must equalTo("Only HAT owner can reset their password")
    }

    "Reset password" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)
        .withJsonBody(Json.toJson(passwordResetStrong))

      val controller   = application.injector.instanceOf[Authentication]
      val tokenService = application.injector.instanceOf[MailTokenUserService]
      val tokenId      = UUID.randomUUID().toString
      val result: Future[Result] = for {
        _ <- tokenService.create(MailTokenUser(tokenId, "user@hat.org", DateTime.now().plusHours(1), isSignUp = false))
        result <- Helpers.call(controller.handleResetPassword(tokenId), request)
      } yield result

      logger.warn(s"reset pass response: ${contentAsJson(result)}")

      status(result) must equalTo(OK)
    }

    "Return status 401 if no owner exists (should never happen)" in {
      val request = FakeRequest("POST", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)
        .withJsonBody(Json.toJson(passwordResetStrong))

      val controller   = application.injector.instanceOf[Authentication]
      val tokenService = application.injector.instanceOf[MailTokenUserService]
      val tokenId      = UUID.randomUUID().toString
      val usersService = application.injector.instanceOf[UsersService]

      val result: Future[Result] = for {
        _ <- tokenService.create(MailTokenUser(tokenId, "user@hat.org", DateTime.now().plusHours(1), isSignUp = false))
        _ <- usersService.saveUser(
               owner.copy(roles = Seq(DataDebitOwner("")))
             ) // forcing owner user to a different role for the test
        result <- Helpers.call(controller.handleResetPassword(tokenId), request)
      } yield result

      status(result) must equalTo(UNAUTHORIZED)
      (contentAsJson(result) \ "cause").as[String] must equalTo("No user matching token")
    }
  }
   */
}

trait AuthenticationContext {
  val passwordChangeIncorrect = ApiPasswordChange("some-passwords-are-better-than-others", Some("wrongOldPassword"))
  val passwordChangeSimple    = ApiPasswordChange("simple", Some("pa55w0rd"))
  val passwordChangeStrong    = ApiPasswordChange("some-passwords-are-better-than-others", Some("pa55w0rd"))
  val passwordResetStrong     = ApiPasswordChange("some-passwords-are-better-than-others", None)

  val passwordForgottenIncorrect = ApiPasswordResetRequest("email@example.com")
  val passwordForgottenOwner     = ApiPasswordResetRequest("user@hat.org")

  val passwordValidationIncorrect = ApiValidationRequest("email@example.com", "appId")
  val passwordValidationOwner     = ApiValidationRequest("user@hat.org", "appId")
}
