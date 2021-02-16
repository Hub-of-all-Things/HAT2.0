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

import java.io.StringReader

import scala.concurrent.{ Await }
import scala.concurrent.duration._

import com.atlassian.jwt.core.keys.KeyUtils
import com.dimafeng.testcontainers.ForAllTestContainer
import com.dimafeng.testcontainers.PostgreSQLContainer
import com.google.inject.AbstractModule
import com.google.inject.Provides
import com.mohiva.play.silhouette.api.Environment
import com.mohiva.play.silhouette.api.LoginInfo
import com.mohiva.play.silhouette.api.crypto.Base64AuthenticatorEncoder
import com.mohiva.play.silhouette.impl.authenticators.JWTRS256AuthenticatorSettings
import com.mohiva.play.silhouette.test._
import com.mohiva.play.silhouette.test._
import io.dataswift.test.common.BaseSpec
import net.codingwell.scalaguice.ScalaModule
import org.hatdex.hat.FakeCache
import org.hatdex.hat.api.models.DataDebitOwner
import org.hatdex.hat.api.models.Owner
import org.hatdex.hat.api.models.{ Platform => DSPlatform }
import org.hatdex.hat.api.service.MailTokenUserService
import org.hatdex.hat.api.service.UsersService
import org.hatdex.hat.api.service.applications.TestApplicationProvider
import org.hatdex.hat.api.service.applications.TrustedApplicationProvider
import org.hatdex.hat.authentication.HatApiAuthEnvironment
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.helpers.{ ContainerUtils }
import org.hatdex.hat.phata.models.ApiPasswordChange
import org.hatdex.hat.phata.models.ApiPasswordResetRequest
import org.hatdex.hat.phata.models.ApiValidationRequest
import org.hatdex.hat.phata.models.MailTokenUser
import org.hatdex.hat.resourceManagement.HatDatabaseProvider
import org.hatdex.hat.resourceManagement.HatDatabaseProviderConfig
import org.hatdex.hat.resourceManagement.HatKeyProvider
import org.hatdex.hat.resourceManagement.HatKeyProviderConfig
import org.hatdex.hat.resourceManagement.HatServer
import org.hatdex.hat.resourceManagement.HatServerProvider
import org.hatdex.hat.resourceManagement.HatServerProviderImpl
import org.hatdex.hat.utils.LoggingProvider
import org.hatdex.hat.utils.MockLoggingProvider
import org.hatdex.libs.dal.HATPostgresProfile.backend.Database
import org.joda.time.DateTime
import org.scalatest._
import org.scalatestplus.play.guice.GuiceOneAppPerTest
import play.api.Configuration
import play.api.Logger
import play.api.cache.AsyncCacheApi
import play.api.http.HeaderNames
import play.api.http.MimeTypes
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.json.JsValue
import play.api.libs.json.Json
import play.api.test.FakeHeaders
import play.api.test.FakeRequest
import play.api.test.Helpers
import play.api.test.Helpers._
import play.api.{ Application => PlayApplication }
import play.libs.akka.AkkaGuiceSupport

class AuthenticationSpec
    extends BaseSpec
    with ContainerUtils
    with AuthenticationContext
    with ForAllTestContainer
    with GuiceOneAppPerTest {

  import scala.concurrent.ExecutionContext.Implicits.global
  val logger = Logger(this.getClass)

  // split this out
  class FakeModule extends AbstractModule with ScalaModule with AkkaGuiceSupport {
    override def configure(): Unit = {
      // bindActor[HatServerProviderActor]("hatServerProviderActor")
      // bindActorFactory[HatServerActor, HatServerActor.Factory]
      bind[HatDatabaseProvider].to[HatDatabaseProviderConfig]
      bind[HatKeyProvider].to[HatKeyProviderConfig]
      bind[HatServerProvider].to[HatServerProviderImpl]
      bind[AsyncCacheApi].to[FakeCache]
      bind[LoggingProvider].toInstance(new MockLoggingProvider(logger))
      bind[TrustedApplicationProvider].toInstance(new TestApplicationProvider(Seq()))
    }

    @Provides @play.cache.NamedCache("hatserver-cache")
    def provideHatServerCache(): AsyncCacheApi =
      new FakeCache()
  }

  // Ephemeral PG Container for this test suite
  override val container = PostgreSQLContainer()
  container.start()
  val conf = containerToConfig(container)

  val hatAddress        = "hat.hubofallthings.net"
  val hatUrl            = s"https://$hatAddress"
  private val hatConfig = conf.get[Configuration](s"hat.$hatAddress")

  private val keyUtils = new KeyUtils()
  implicit val db: Database = Database.forURL(
    url = container.jdbcUrl,
    user = container.username,
    password = container.password
  )

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
    .configure(conf)
    .overrides(new FakeModule)
    .build()

  val owner = new HatUser(
    userId = java.util.UUID.randomUUID(),
    email = "user@hat.org",
    pass = Some("$2a$06$QprGa33XAF7w8BjlnKYb3OfWNZOuTdzqKeEsF7BZUfbiTNemUW/n."),
    name = "hat",
    roles = Seq(Owner(), DSPlatform()),
    enabled = true
  )

  val dataDebitUser = HatUser(
    java.util.UUID.randomUUID(),
    "dataDebitUser",
    Some("$2a$06$QprGa33XAF7w8BjlnKYb3OfWNZOuTdzqKeEsF7BZUfbiTNemUW/n."),
    "dataDebitUser",
    Seq(DataDebitOwner("")),
    enabled = true
  )

  val userService = application.injector.instanceOf[UsersService]
  userService.saveUser(owner)
  userService.saveUser(dataDebitUser)

  val controller            = application.injector.instanceOf[Authentication]
  implicit val materializer = application.materializer

  implicit val environment: Environment[HatApiAuthEnvironment] =
    FakeEnvironment[HatApiAuthEnvironment](
      Seq(owner.loginInfo -> owner, dataDebitUser.loginInfo -> dataDebitUser),
      hatServer
    )

  // KO - times out
  "The `publicKey` method" should "Return public key of the HAT" in {
    val request = FakeRequest("GET", hatUrl)

    val result = Helpers.call(controller.publicKey(), request)

    status(result) must equal(OK)

    contentAsString(result) must startWith("-----BEGIN PUBLIC KEY-----\n")
  }

  // // OK
  "The `validateToken` method" should "return status 401 if authenticator but no identity was found" in {
    val request = FakeRequest("GET", hatUrl)
      .withAuthenticator(LoginInfo("xing", "comedian@watchmen.com"))

    val result = Helpers.call(controller.validateToken(), request)

    status(result) must equal(UNAUTHORIZED)
  }

  // KO - 401, not 200
  it should "Return simple success message for a valid token" in {
    val request = FakeRequest("GET", hatUrl)
      .withAuthenticator(owner.loginInfo)

    val result = Helpers.call(controller.validateToken(), request)

    status(result) must equal(OK)
    (contentAsJson(result) \ "message").as[String] must equal("Authenticated")
  }

  // OK
  "The `hatLogin` method" should "return status 401 if authenticator but no identity was found" in {
    val request = FakeRequest("GET", hatUrl)
      .withAuthenticator(LoginInfo("xing", "comedian@watchmen.com"))

    val result = Helpers.call(controller.hatLogin("TestService", "http://testredirect"), request)

    status(result) must equal(UNAUTHORIZED)
  }

  // KO
  it should "return status 403 if authenticator and existing identity but wrong role" in {
    val request = FakeRequest("POST", hatUrl)
      .withAuthenticator(dataDebitUser.loginInfo)

    val result = Helpers.call(controller.hatLogin("TestService", "http://testredirect"), request)

    status(result) must equal(FORBIDDEN)
  }

  it should "return redirect url for authenticated owner" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val result = Helpers.call(controller.hatLogin("TestService", "http://testredirect"), request)

    status(result) must equal(OK)
    contentAsString(result) must contain("testredirect")
    contentAsString(result) must contain("token=")
  }

  "The `accessToken` method" should "return status 401 if no credentials provided" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")

    val result = Helpers.call(controller.accessToken(), request)

    status(result) must equal(UNAUTHORIZED)
  }

  it should "return status 403 if credentials but no matching identity" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withHeaders("username" -> "test", "password" -> "foo")

    val controller = application.injector.instanceOf[Authentication]
    //an[IdentityNotFoundException] should be thrownBy (controller.accessToken().apply(request))
    val result = Helpers.call(controller.accessToken(), request)

    status(result) must equal(FORBIDDEN)
  }

  it should "return Access Token for the authenticated user" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withHeaders("username" -> "hat", "password" -> "pa55w0rd")

    val controller = application.injector.instanceOf[Authentication]

    val encoder  = new Base64AuthenticatorEncoder()
    val settings = JWTRS256AuthenticatorSettings("X-Auth-Token", None, "hat.org", Some(3.days), 3.days)

    val result = Helpers.call(controller.accessToken(), request)

    status(result) must equal(OK)
    //val token        = (contentAsJson(result) \ "accessToken").as[String]
    //val unserialized = JWTRS256Authenticator.unserialize(token, encoder, settings)
    // unserialized must beSuccessfulTry
    // unserialized.get.loginInfo must be equalTo owner.loginInfo
  }

  "The `passwordChangeProcess` method" should "return status 403 if not owner" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(dataDebitUser.loginInfo)
      .withJsonBody(Json.toJson(passwordChangeIncorrect))

    val controller = application.injector.instanceOf[Authentication]
    val result     = Helpers.call(controller.passwordChangeProcess(), request)

    status(result) must equal(FORBIDDEN)
  }

  it should "return status 403 if old password incorrect" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(passwordChangeIncorrect))

    val controller = application.injector.instanceOf[Authentication]
    val result     = Helpers.call(controller.passwordChangeProcess(), request)

    status(result) must equal(FORBIDDEN)
  }

  it should "return status 400 if new password too weak" in {
    val request = FakeRequest[JsValue](
      Helpers.POST,
      "/control/v2/auth/password",
      headers = FakeHeaders(Seq((HeaderNames.ACCEPT, MimeTypes.JSON), (HeaderNames.CONTENT_TYPE, MimeTypes.JSON))),
      body = Json.toJson(passwordChangeSimple),
      remoteAddress = "hat.hubofallthings.net"
    )
      .withAuthenticator(owner.loginInfo)

    // WTF is this?
    //val maybeResult: Option[Future[Result]] = Helpers.route(application, request)
    // maybeResult must be('defined)
    // val result = maybeResult.get

    val controller = application.injector.instanceOf[Authentication]
    val result     = Helpers.call(controller.passwordChangeProcess(), request)

    status(result) must equal(BAD_REQUEST)
    contentType(result) must equal("application/json")
    (contentAsJson(result) \ "error").as[String] must equal("Bad Request")
  }

  it should "Change password if it is sufficiently strong" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(passwordChangeStrong))

    val controller = application.injector.instanceOf[Authentication]
    val result     = Helpers.call(controller.passwordChangeProcess(), request)

    status(result) must equal(OK)
    (contentAsJson(result) \ "message").as[String] must equal("Password changed")
  }

  "The `handleForgotPassword` method should" should "Hide the fact that email doesn't match by returning status 200" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(dataDebitUser.loginInfo)
      .withJsonBody(Json.toJson(passwordForgottenIncorrect))

    val controller = application.injector.instanceOf[Authentication]
    val result     = Helpers.call(controller.handleForgotPassword, request)

    status(result) must equal(OK)
  }

  it should "Send email to the owner if provided email matches" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(dataDebitUser.loginInfo)
      .withJsonBody(Json.toJson(passwordForgottenOwner))

    val controller = application.injector.instanceOf[Authentication]
    val result     = Helpers.call(controller.handleForgotPassword, request)

    status(result) must equal(OK)
    //there was one(mockMailer).passwordReset(any[String], any[String])(any[MessagesApi], any[Lang], any[HatServer])
  }

  "The `handleResetPassword` method" should "Return status 401 if no such token exists" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(dataDebitUser.loginInfo)
      .withJsonBody(Json.toJson(passwordResetStrong))

    val controller = application.injector.instanceOf[Authentication]
    val result     = Helpers.call(controller.handleResetPassword("nosuchtoken"), request)

    status(result) must equal(UNAUTHORIZED)
    (contentAsJson(result) \ "cause").as[String] must equal("Token does not exist")
  }

  it should "Return status 401 if token has expired" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(passwordResetStrong))

    val controller   = application.injector.instanceOf[Authentication]
    val tokenService = application.injector.instanceOf[MailTokenUserService]
    val tokenId      = java.util.UUID.randomUUID().toString

    val result = for {
      _ <- tokenService.create(MailTokenUser(tokenId, "hat@hat.org", DateTime.now().minusHours(1), isSignUp = false))
      result <- Helpers.call(controller.handleResetPassword(tokenId), request)
    } yield result

    status(result) must equal(UNAUTHORIZED)
    (contentAsJson(result) \ "cause").as[String] must equal("Token expired or invalid")
  }

  it should "Return status 401 if token email doesn't match owner" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(passwordResetStrong))

    val controller   = application.injector.instanceOf[Authentication]
    val tokenService = application.injector.instanceOf[MailTokenUserService]
    val tokenId      = java.util.UUID.randomUUID().toString

    val result = for {
      _ <- tokenService.create(MailTokenUser(tokenId, "email@hat.org", DateTime.now().plusHours(1), isSignUp = false))
      result <- Helpers.call(controller.handleResetPassword(tokenId), request)
    } yield result

    status(result) must equal(UNAUTHORIZED)
    (contentAsJson(result) \ "cause").as[String] must equal("Only HAT owner can reset their password")
  }

  it should "Reset password" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(passwordResetStrong))

    val controller   = application.injector.instanceOf[Authentication]
    val tokenService = application.injector.instanceOf[MailTokenUserService]
    val tokenId      = java.util.UUID.randomUUID().toString
    val result = for {
      _ <- tokenService.create(MailTokenUser(tokenId, "user@hat.org", DateTime.now().plusHours(1), isSignUp = false))
      result <- Helpers.call(controller.handleResetPassword(tokenId), request)
    } yield result

    status(result) must equal(OK)
  }

  it should "Return status 401 if no owner exists (should never happen)" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(passwordResetStrong))

    val controller   = application.injector.instanceOf[Authentication]
    val tokenService = application.injector.instanceOf[MailTokenUserService]
    val tokenId      = java.util.UUID.randomUUID().toString
    val usersService = application.injector.instanceOf[UsersService]

    val result = for {
      _ <- tokenService.create(MailTokenUser(tokenId, "user@hat.org", DateTime.now().plusHours(1), isSignUp = false))
      _ <- usersService.saveUser(
             owner.copy(roles = Seq(DataDebitOwner("")))
           ) // forcing owner user to a different role for the test
      result <- Helpers.call(controller.handleResetPassword(tokenId), request)
    } yield result

    status(result) must equal(UNAUTHORIZED)
    (contentAsJson(result) \ "cause").as[String] must equal("No user matching token")
  }

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
