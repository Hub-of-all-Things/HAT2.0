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

package org.hatdex.hat.api.service.applications

import akka.Done
import akka.util.ByteString
import com.google.inject.AbstractModule
import net.codingwell.scalaguice.ScalaModule
import org.hatdex.hat.api.HATTestContext
import org.hatdex.hat.api.models.applications.ApplicationKind.{ App, Contract }
import org.hatdex.hat.api.models.applications._
import org.hatdex.hat.api.models._
import org.hatdex.hat.api.service.StatsReporter
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, HatServer }
import org.joda.time.{ DateTime, LocalDateTime }
import org.mockito.Mockito.when
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import play.api.http.HttpEntity
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.json.Json
import play.api.libs.ws.WSClient
import play.api.test.FakeRequest
import play.api.{ Logger, Application => PlayApplication }
import play.core.server.Server

import scala.concurrent.Future

trait ApplicationsServiceContext extends HATTestContext {
  override lazy val application: PlayApplication = new GuiceApplicationBuilder()
    .configure(FakeHatConfiguration.config)
    .overrides(new FakeModule)
    .overrides(new CustomisedFakeModule)
    .build()

  import scala.concurrent.ExecutionContext.Implicits.global

  private val logger = Logger(this.getClass)

  import play.api.mvc._
  import play.api.routing.sird._

  val kind: ApplicationKind.Kind = App(
    url = "https://itunes.apple.com/gb/app/notables/id1338778866?mt=8",
    iosUrl = Some("https://itunes.apple.com/gb/app/notables/id1338778866?mt=8"),
    androidUrl = None
  )

  val contractKind: ApplicationKind.Kind = Contract("https://dataswift.io")

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

  val fakeContract: Application =
    Application(
      id = "21a3eed7-5d32-46ba-a884-1fdaf7259731",
      kind = contractKind,
      info = appInfo,
      developer = developer,
      permissions = permissions,
      dependencies = None,
      setup = setup,
      status = status
    )

  val notablesAppDebitless: Application =
    notablesApp.copy(id = "notables-debitless", permissions = notablesApp.permissions.copy(dataRetrieved = None))
  val notablesAppMissing: Application = notablesAppDebitless.copy(
    id = "notables-missing",
    permissions = notablesApp.permissions.copy(
      dataRetrieved = Some(
        notablesApp.permissions.dataRetrieved.get
          .copy(name = "notables-missing-bundle")
      )
    )
  )
  val notablesAppIncompatible: Application = notablesApp.copy(
    id = "notables-incompatible",
    permissions = notablesApp.permissions.copy(
      dataRetrieved = Some(
        notablesApp.permissions.dataRetrieved.get
          .copy(name = "notables-incompatible-bundle")
      )
    )
  )
  val notablesAppIncompatibleUpdated: Application =
    notablesAppIncompatible.copy(info = notablesApp.info.copy(version = Version("1.1.0")),
                                 status = ApplicationStatus
                                   .Internal(Version("1.1.0"), None, None, None, DateTime.now())
    )

  val notablesAppExternal: Application = notablesApp.copy(
    id = "notables-external",
    status = ApplicationStatus.External(Version("1.0.0"), "/status", 200, None, None, None, DateTime.now()),
    permissions = notablesApp.permissions.copy(
      dataRetrieved = Some(
        notablesApp.permissions.dataRetrieved.get
          .copy(name = "notables-external")
      )
    )
  )
  val notablesAppExternalFailing: Application = notablesApp.copy(
    id = "notables-external-failing",
    status = ApplicationStatus.External(Version("1.0.0"), "/failing", 200, None, None, None, DateTime.now()),
    permissions = notablesApp.permissions.copy(
      dataRetrieved = Some(notablesApp.permissions.dataRetrieved.get.copy(name = "notables-external-failing"))
    )
  )
  val notablesAppDebitlessWithPlugDependency = notablesAppDebitless.copy(
    id = "notables-plug-dependency",
    dependencies = Some(ApplicationDependencies(List("plug-app").toArray, List().toArray, List().toArray))
  )
  val notablesAppDebitlessWithInvalidDependency = notablesAppDebitless.copy(
    id = "notables-invalid-dependency",
    dependencies = Some(ApplicationDependencies(List("invalid-id").toArray, List().toArray, List().toArray))
  )
  val plugApp = notablesAppDebitless.copy(id = "plug-app", kind = ApplicationKind.DataPlug("http://dataplug.hat.org"))

  def withMockWsClient[T](block: WSClient => T): T =
    Server.withRouterFromComponents() { components =>
      import components.{ defaultActionBuilder => Action }
      {
        case GET(p"/status") =>
          Action {
            Results.Ok.sendEntity(HttpEntity.Strict(ByteString("OK"), Some("text/plain")))
          }
        case GET(p"/failing") =>
          Action {
            Results.Forbidden.sendEntity(HttpEntity.Strict(ByteString("FORBIDDEN"), Some("text/plain")))
          }
      }
    } { implicit port =>
      logger.info(s"Creating test client at port $port")
      play.api.test.WsTestClient.withClient { client =>
        block(client)
      }
    }

  lazy val mockStatusChecker = {

    case class StatusCheck() extends Answer[Future[Boolean]] {
      override def answer(invocation: InvocationOnMock) = {
        val s =
          invocation.getArguments()(0).asInstanceOf[ApplicationStatus.Status]
        s match {
          case ApplicationStatus.Internal(_, _, _, _, _) =>
            Future.successful(true)
          case ApplicationStatus.External(_, "/status", _, _, _, _, _) =>
            Future.successful(true)
          case _ => Future.successful(false)
        }
      }
    }

    val mockStatusChecker = mock[ApplicationStatusCheckService]
    mockStatusChecker.status(any[ApplicationStatus.Internal], any[String]) returns Future
      .successful(true)
    when(mockStatusChecker.status(any[ApplicationStatus.Status], any[String]))
      .thenAnswer(StatusCheck())

    mockStatusChecker

  }

  lazy val mockStatsReporter = {
    val mockStatsReporter = mock[StatsReporter]
    mockStatsReporter.registerOwnerConsent(any[String])(any[HatServer]) returns Future
      .successful(Done)

    mockStatsReporter
  }

  class CustomisedFakeModule extends AbstractModule with ScalaModule {
    override def configure(): Unit = {
      bind[TrustedApplicationProvider].toInstance(
        new TestApplicationProvider(
          Seq(
            notablesApp,
            notablesAppDebitless,
            notablesAppIncompatibleUpdated,
            notablesAppExternal,
            notablesAppExternalFailing,
            notablesAppDebitlessWithPlugDependency,
            notablesAppDebitlessWithInvalidDependency,
            plugApp
          )
        )
      )

      bind[ApplicationStatusCheckService].toInstance(mockStatusChecker)
      bind[StatsReporter].toInstance(mockStatsReporter)
    }
  }

  implicit val fakeRequest: RequestHeader =
    FakeRequest("GET", "http://hat.hubofallthings.net")
  implicit val ownerImplicit: HatUser = owner
}
