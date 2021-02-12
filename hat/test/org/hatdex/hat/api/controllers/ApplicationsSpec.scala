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
import org.specs2.mock.Mockito
import org.specs2.specification.{ BeforeAll, BeforeEach }
import play.api.Logger
import play.api.test.{ FakeRequest, PlaySpecification }
import io.dataswift.test.common.BaseSpec
import com.dimafeng.testcontainers.{ ForAllTestContainer, PostgreSQLContainer }
import org.hatdex.hat.helpers.{ ContainerUtils }
import ApplicationJsonProtocol._
import org.hatdex.hat.api.json.HatJsonFormats.{ accessTokenFormat, errorMessage }
import org.hatdex.hat.authentication.models.HatUser
import play.api.Configuration
import java.io.StringReader
import org.hatdex.libs.dal.HATPostgresProfile.backend.Database
import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, HatServer }
import akka.stream.Materializer
import com.atlassian.jwt.core.keys.KeyUtils
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.{ Logger, Application => PlayApplication }
import play.api.test.Helpers
import play.api.test.Helpers._
import play.api.test.FakeRequest
import org.hatdex.hat.api.models.{ Owner, Platform => DSPlatform, DataDebitOwner }
import org.hatdex.hat.api.service.UsersService
import scala.concurrent.Await
import scala.concurrent.duration._
import com.mohiva.play.silhouette.api._
import com.google.inject.AbstractModule
import net.codingwell.scalaguice.ScalaModule
import org.hatdex.hat.resourceManagement.FakeHatServerProvider
import org.hatdex.hat.resourceManagement.HatServerProvider
import org.hatdex.hat.api.service.MailTokenService
import org.hatdex.hat.api.service.MailTokenUserService
import org.hatdex.hat.phata.models.MailTokenUser
import play.cache.AsyncCacheApi
import play.cache.NamedCacheImpl
import org.hatdex.hat.FakeCache
import org.hatdex.hat.utils.LoggingProvider
import org.hatdex.hat.utils.MockLoggingProvider
import play.api.http.HttpErrorHandler
import org.hatdex.hat.utils.ErrorHandler
import org.hatdex.hat.api.service.applications.TrustedApplicationProvider
import org.hatdex.hat.api.service.applications.TestApplicationProvider
import org.hatdex.hat.api.models.applications.ApplicationKind
import org.hatdex.hat.api.models.applications.ApplicationKind._
import org.hatdex.hat.api.models.applications._
import org.hatdex.hat.api.models.Drawable
import org.joda.time.DateTime
import org.hatdex.hat.api.models._
import org.hatdex.hat.api.service.applications.ApplicationStatusCheckService
import org.hatdex.hat.api.service.StatsReporter
import play.api.libs.json.Json
import org.joda.time.LocalDateTime
import org.hatdex.hat.api.service.applications.ApplicationsService
import com.mohiva.play.silhouette.api.SilhouetteProvider
import play.api.test.WithApplication

class ApplicationsSpec
    extends BaseSpec
    with ContainerUtils /*with ApplicationsServiceContext*/
    with ForAllTestContainer {

  // ------------------------

  import scala.concurrent.ExecutionContext.Implicits.global
  // Ephemeral PG Container for this test suite
  override val container = PostgreSQLContainer()
  container.start()
  val conf = containerToConfig(container)

  val logger            = Logger(this.getClass)
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

  implicit val environment: Environment[HatApiAuthEnvironment] =
    FakeEnvironment[HatApiAuthEnvironment](
      Seq(owner.loginInfo -> owner, dataDebitUser.loginInfo -> dataDebitUser),
      hatServer
    )

  class FakeModule extends AbstractModule with ScalaModule {
    override def configure(): Unit = {
      bind[Environment[HatApiAuthEnvironment]].toInstance(environment)
      bind[Silhouette[HatApiAuthEnvironment]].to[SilhouetteProvider[HatApiAuthEnvironment]]
      bind[HatServerProvider].toInstance(new FakeHatServerProvider(hatServer))
      bind[MailTokenService[MailTokenUser]].to[MailTokenUserService]
      bind[HttpErrorHandler].to[ErrorHandler]
      //bind[ApplicationsService].to[ApplicationsService]
      //bind[AsyncCacheApi].annotatedWith(new NamedCacheImpl("user-cache")).to[FakeCache]
      //bind[AsyncCacheApi].to[FakeCache]
      //bind[LoggingProvider].toInstance(new MockLoggingProvider(mockLogger))
      println("FakeModule")
    }
  }

  val kind: ApplicationKind.Kind = App(
    url = "https://itunes.apple.com/gb/app/notables/id1338778866?mt=8",
    iosUrl = Some("https://itunes.apple.com/gb/app/notables/id1338778866?mt=8"),
    androidUrl = None
  )

  val dataPreview: Seq[DataFeedItem] = List(
    DataFeedItem(
      source = "notables",
      date = DateTime.parse("2018-02-15T03:52:37.000Z"),
      types = List("note"),
      title = Some(DataFeedItemTitle(text = "leila.hubat.net", subtitle = None, action = Some("private"))),
      content = Some(DataFeedItemContent(text = Some("Notes are live!"), None, None, None)),
      location = None
    ),
    DataFeedItem(
      source = "notables",
      date = DateTime.parse("2018-02-15T03:52:37.317Z"),
      types = List("note"),
      title = Some(DataFeedItemTitle(text = "leila.hubat.net", subtitle = None, action = Some("private"))),
      content = Some(DataFeedItemContent(text = Some("And I love 'em!"), None, None, None)),
      location = None
    )
  )

  val description = FormattedText(
    text =
      "\n Anything you write online is your data – searches, social media posts, comments and notes.\n\n Start your notes here on Notables, where they will be stored completely privately in your HAT.\n\n Use Notables to draft and share social media posts. You can set how long they stay on Twitter or Facebook – a day, a week or a month. You can always set them back to private later: it will disappear from your social media but you won’t lose it because it’s saved in your HAT.\n\n Add images or pin locations as reminders of where you were or what you saw.\n          ",
    markdown = Some(
      "\n Anything you write online is your data – searches, social media posts, comments and notes.\n\n Start your notes here on Notables, where they will be stored completely privately in your HAT.\n\n Use Notables to draft and share social media posts. You can set how long they stay on Twitter or Facebook – a day, a week or a month. You can always set them back to private later: it will disappear from your social media but you won’t lose it because it’s saved in your HAT.\n\n Add images or pin locations as reminders of where you were or what you saw.\n          "
    ),
    html = Some(
      "\n <p>Anything you write online is your data – searches, social media posts, comments and notes.</p>\n\n <p>Start your notes here on Notables, where they will be stored completely privately in your HAT.</p>\n\n <p>Use Notables to draft and share social media posts. You can set how long they stay on Twitter or Facebook – a day, a week or a month. You can always set them back to private later: it will disappear from your social media but you won’t lose it because it’s saved in your HAT.</p>\n\n <p>Add images or pin locations as reminders of where you were or what you saw.</p>\n          "
    )
  )

  val graphics = ApplicationGraphics(
    banner = Drawable(normal = "", small = None, large = None, xlarge = None),
    logo = Drawable(
      normal =
        "https://s3-eu-west-1.amazonaws.com/hubofallthings-com-dexservi-dexpublicassetsbucket-kex8hb7fsdge/notablesapp/0x0ss.png",
      small = None,
      large = None,
      xlarge = None
    ),
    screenshots = List(
      Drawable(
        normal =
          "https://s3-eu-west-1.amazonaws.com/hubofallthings-com-dexservi-dexpublicassetsbucket-kex8hb7fsdge/notablesapp/0x0ss.jpg",
        large = Some(
          "https://s3-eu-west-1.amazonaws.com/hubofallthings-com-dexservi-dexpublicassetsbucket-kex8hb7fsdge/notablesapp/0x0ss-5.jpg"
        ),
        small = None,
        xlarge = None
      ),
      Drawable(
        normal =
          "https://s3-eu-west-1.amazonaws.com/hubofallthings-com-dexservi-dexpublicassetsbucket-kex8hb7fsdge/notablesapp/0x0ss-2.jpg",
        large = Some(
          "https://s3-eu-west-1.amazonaws.com/hubofallthings-com-dexservi-dexpublicassetsbucket-kex8hb7fsdge/notablesapp/0x0ss-6.jpg"
        ),
        small = None,
        xlarge = None
      ),
      Drawable(
        normal =
          "https://s3-eu-west-1.amazonaws.com/hubofallthings-com-dexservi-dexpublicassetsbucket-kex8hb7fsdge/notablesapp/0x0ss-3.jpg",
        large = Some(
          "https://s3-eu-west-1.amazonaws.com/hubofallthings-com-dexservi-dexpublicassetsbucket-kex8hb7fsdge/notablesapp/0x0ss-7.jpg"
        ),
        small = None,
        xlarge = None
      )
    )
  )

  val appInfo: ApplicationInfo = ApplicationInfo(
    version = Version(1, 0, 0),
    updateNotes = None,
    published = true,
    name = "Notables",
    headline = "All your words",
    description = description,
    hmiDescription = None,
    termsUrl = "https://example.com/terms",
    privacyPolicyUrl = None,
    dataUsePurpose = "Data Will be processed by Notables for the following purpose...",
    supportContact = "contact@hatdex.org",
    rating = None,
    dataPreview = dataPreview,
    graphics: ApplicationGraphics,
    primaryColor = None,
    callbackUrl = None
  )

  val developer = ApplicationDeveloper(
    id = "dex",
    name = "HATDeX",
    url = "https://hatdex.org",
    country = Some("United Kingdom"),
    logo = Some(
      Drawable(
        normal =
          "https://s3-eu-west-1.amazonaws.com/hubofallthings-com-dexservi-dexpublicassetsbucket-kex8hb7fsdge/notablesapp/0x0ss.png",
        small = None,
        large = None,
        xlarge = None
      )
    )
  )

  val dataRetrieved = EndpointDataBundle(
    name = "notablesapp",
    bundle = Map(
      "profile" -> PropertyQuery(
            endpoints = List(
              EndpointQuery(
                endpoint = "rumpel/notablesv1",
                mapping = Some(Json.parse("""{
            |                                        "name": "personal.preferredName",
            |                                        "nick": "personal.nickName",
            |                                        "photo_url": "photo.avatar"
            |                                    }""".stripMargin)),
                filters = Some(
                  List(
                    EndpointQueryFilter(field = "shared",
                                        transformation = None,
                                        operator = FilterOperator.Contains(Json.parse("true"))
                    )
                  )
                ),
                links = None
              )
            ),
            orderBy = Some("updated_time"),
            ordering = Some("descending"),
            limit = Some(1)
          )
    )
  )

  val dataRequired = DataDebitRequest(
    bundle = dataRetrieved,
    conditions = None,
    startDate = LocalDateTime.parse("2018-02-15T03:52:38"),
    endDate = LocalDateTime.parse("2019-02-15T03:52:38"),
    rolling = true
  )

  val permissions = ApplicationPermissions(
    rolesGranted = List(
      UserRole.userRoleDeserialize("namespacewrite", Some("rumpel")),
      UserRole.userRoleDeserialize("namespaceread", Some("rumpel")),
      UserRole.userRoleDeserialize("datadebit", Some("app-notables"))
    ),
    dataRetrieved = Some(dataRetrieved),
    dataRequired = Some(dataRequired)
  )

  val setup = ApplicationSetup.External(
    url = None,
    iosUrl = Some("notablesapp://notablesapphost"),
    androidUrl = None,
    testingUrl = None,
    validRedirectUris = List.empty,
    deauthorizeCallbackUrl = None,
    onboarding = None,
    preferences = None,
    dependencies = None
  )

  val status = ApplicationStatus.Internal(
    compatibility = Version(1, 0, 0),
    dataPreviewEndpoint = None,
    staticDataPreviewEndpoint = None,
    recentDataCheckEndpoint = Some("/rumpel/notablesv1"),
    versionReleaseDate = DateTime.parse("2018-07-24T12:00:00")
  )

  val notablesApp: Application =
    Application(id = "notables",
                kind = kind,
                info = appInfo,
                developer = developer,
                permissions = permissions,
                dependencies = None,
                setup = setup,
                status = status
    )

  class CustomisedFakeModule extends AbstractModule with ScalaModule {
    override def configure(): Unit =
      bind[TrustedApplicationProvider].toInstance(
        new TestApplicationProvider(
          Seq(
            notablesApp
          )
        )
      )

    // bind[ApplicationStatusCheckService].toInstance(mockStatusChecker)
    // bind[StatsReporter].toInstance(mockStatsReporter)
  }

  val application: PlayApplication = new GuiceApplicationBuilder()
    .configure(conf)
    .overrides(new FakeModule)
    .overrides(new CustomisedFakeModule)
    .build()

//  implicit lazy val materializer: Materializer = application.materializer

  val userService = application.injector.instanceOf[UsersService]
  userService.saveUser(owner)
  userService.saveUser(dataDebitUser)

  val controller = application.injector.instanceOf[Authentication]

  // ------------------------

  // "The `user` method" should "return status 401 if no authenticator was found" in new WithApplication {
  //   val request = FakeRequest()

  //   val controller = application.injector.instanceOf[Authentication]
  //   val result     = Helpers.call(controller.accessToken, request)

  //   val r = Await.result(result, 10.seconds)
  //   r must equal(UNAUTHORIZED)

  // }

  "The `applications` method" should "Return list of available applications" in new WithApplication {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[Applications]
    val result     = controller.applicationStatus("random-id").apply(request)

    //status(result) must equal(NOT_FOUND)
    val error = contentAsJson(result).as[ErrorMessage]
    error.message must equal("Application not Found")

    // val request = FakeRequest("GET", "http://hat.hubofallthings.net")
    //   .withAuthenticator(owner.loginInfo)

    // implicit val applicationsService = application.injector.instanceOf[ApplicationsService]
    // val controller                   = application.injector.instanceOf[Applications]

    // val result = Helpers.call(controller.applications(), request)

    // Helpers.status(result) must equal(OK)
    // contentAsJson(result).validate[Seq[HatApplication]].isSuccess must equal(true)
    // val apps = contentAsJson(result).as[Seq[HatApplication]]
    // apps.length must equal(8)
    // apps.find(_.application.id == notablesApp.id) must beSome
    // apps.find(_.application.id == notablesAppDebitless.id) must beSome
    // apps.find(_.application.id == notablesAppIncompatible.id) must beSome
  }

  /*
  "The `applicationStatus` method" should {
    "Return status of a single application" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)

      val controller = application.injector.instanceOf[Applications]
      val result     = controller.applicationStatus(notablesApp.id).apply(request)

      status(result) must equalTo(OK)
      val app = contentAsJson(result).as[HatApplication]
      app.application.info.name must be equalTo notablesApp.info.name
    }

    "Return 404 for a non-existent application" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)

      val controller = application.injector.instanceOf[Applications]
      val result     = controller.applicationStatus("random-id").apply(request)

      status(result) must equalTo(NOT_FOUND)
      val error = contentAsJson(result).as[ErrorMessage]
      error.message must be equalTo "Application not Found"
    }
  }

  "The `hmi` method" should {
    "Return the information about the specified application" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")

      val controller = application.injector.instanceOf[Applications]
      val result     = controller.hmi(notablesApp.id).apply(request)

      status(result) must equalTo(OK)
      val app = contentAsJson(result).as[Application]
      app.id must beEqualTo(notablesApp.id)
    }

    "Return 404 for non-existend application" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")

      val controller = application.injector.instanceOf[Applications]
      val result     = controller.hmi("random-id").apply(request)

      status(result) must equalTo(NOT_FOUND)
      val error = contentAsJson(result).as[ErrorMessage]
      error.cause must startWith("Application configuration for ID random-id could not be found")
    }
  }

  "The `applicationSetup` method" should {
    "Return setup application status" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)

      val controller = application.injector.instanceOf[Applications]
      val result     = controller.applicationSetup(notablesApp.id).apply(request)

      status(result) must equalTo(OK)
      val app = contentAsJson(result).as[HatApplication]
      app.application.info.name must be equalTo notablesApp.info.name
      app.setup must be equalTo true
      app.active must be equalTo true
    }

    "Return 404 for a non-existent application" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)

      val controller = application.injector.instanceOf[Applications]
      val result     = controller.applicationSetup("random-id").apply(request)

      status(result) must equalTo(BAD_REQUEST)
      val error = contentAsJson(result).as[ErrorMessage]
      error.message must be equalTo "Application not Found"
    }
  }

  "The `applicationSetup` method" should {
    "Return disabled application status" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)

      val controller = application.injector.instanceOf[Applications]
      val result     = controller.applicationDisable(notablesApp.id).apply(request)

      status(result) must equalTo(OK)
      val app = contentAsJson(result).as[HatApplication]
      app.application.info.name must be equalTo notablesApp.info.name
      app.setup must be equalTo true
      app.active must be equalTo false
    }

    "Return 404 for a non-existent application" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)

      val controller = application.injector.instanceOf[Applications]
      val result     = controller.applicationDisable("random-id").apply(request)

      status(result) must equalTo(BAD_REQUEST)
      val error = contentAsJson(result).as[ErrorMessage]
      error.message must be equalTo "Application not Found"
    }
  }

  "The `applicationToken` method" should {
    "Return 401 Forbidden for application token with no explicit permission" in {
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

      status(result) must equalTo(FORBIDDEN)
      logger.info(s"Got back result ${contentAsString(result)}")
      val error = contentAsJson(result) \ "error"
      error.get.as[String] must be equalTo "Forbidden"
    }

    "Return 404 for application that does not exist" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)

      val controller = application.injector.instanceOf[Applications]
      val result     = controller.applicationToken("random-id").apply(request)

      status(result) must equalTo(NOT_FOUND)
      val error = contentAsJson(result).as[ErrorMessage]
      error.message must be equalTo "Application not Found"
    }

    "Return access token" in {
      val request = FakeRequest("GET", "http://hat.hubofallthings.net")
        .withAuthenticator(owner.loginInfo)

      val controller = application.injector.instanceOf[Applications]
      val result     = controller.applicationToken(notablesApp.id).apply(request)

      status(result) must equalTo(OK)
      val token = contentAsJson(result).as[AccessToken]
      token.accessToken must not beEmpty
    }
  }
   */
}
