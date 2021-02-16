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

import java.io.StringReader

import scala.concurrent.Await
import scala.concurrent.duration._

import com.atlassian.jwt.core.keys.KeyUtils
import com.dimafeng.testcontainers.ForAllTestContainer
import com.dimafeng.testcontainers.PostgreSQLContainer
import com.google.inject.AbstractModule
import com.google.inject.Provides
import com.mohiva.play.silhouette.api.Environment
import com.mohiva.play.silhouette.test.FakeEnvironment
import io.dataswift.test.common.BaseSpec
import net.codingwell.scalaguice.ScalaModule
import org.hatdex.hat.FakeCache
import org.hatdex.hat.api.models.Owner
import org.hatdex.hat.api.models.{ Platform => DSPlatform }
import org.hatdex.hat.api.service.UsersService
import org.hatdex.hat.authentication.HatApiAuthEnvironment
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.helpers.ContainerUtils
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
import org.scalatestplus.play.guice.GuiceOneAppPerTest
import play.api.Configuration
import play.api.Logger
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.concurrent.AkkaGuiceSupport
import play.api.{ Application => PlayApplication }
import play.api.cache.AsyncCacheApi
import org.hatdex.hat.api.models.applications.HatApplication
import org.hatdex.hat.api.service.richData.RichDataService
import org.hatdex.hat.api.models.EndpointData
import play.api.libs.json.JsObject
import play.api.libs.json.JsString
import org.hatdex.hat.api.service.richData.DataDebitService
import org.hatdex.hat.api.service.applications.ApplicationExceptions.HatApplicationSetupException
import com.mohiva.play.silhouette.api.crypto.Base64AuthenticatorEncoder
import com.mohiva.play.silhouette.impl.authenticators.JWTRS256AuthenticatorSettings
import com.mohiva.play.silhouette.impl.authenticators.JWTRS256Authenticator
import scala.util.Success
import scala.util.Failure
import akka.Done

class ApplicationsServiceSpec
    extends BaseSpec
    with ContainerUtils
    with ApplicationsServiceContext
    with ForAllTestContainer
    with GuiceOneAppPerTest {

  import scala.concurrent.ExecutionContext.Implicits.global
  val logger = Logger(this.getClass)

  class FakeModule extends AbstractModule with ScalaModule with AkkaGuiceSupport {
    override def configure(): Unit = {
      bind[HatDatabaseProvider].to[HatDatabaseProviderConfig]
      bind[HatKeyProvider].to[HatKeyProviderConfig]
      bind[HatServerProvider].to[HatServerProviderImpl]
      bind[AsyncCacheApi].to[FakeCache]
      bind[LoggingProvider].toInstance(new MockLoggingProvider(logger))
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

  lazy val application: PlayApplication = new GuiceApplicationBuilder()
    .configure(conf)
    .overrides(new FakeModule)
    //.overrides(new CustomisedFakeModule)
    .build()

  implicit val owner = new HatUser(
    userId = java.util.UUID.randomUUID(),
    email = "user@hat.org",
    pass = Some("$2a$06$QprGa33XAF7w8BjlnKYb3OfWNZOuTdzqKeEsF7BZUfbiTNemUW/n."),
    name = "hat",
    roles = Seq(Owner(), DSPlatform()),
    enabled = true
  )

  val userService = application.injector.instanceOf[UsersService]
  userService.saveUser(owner)

  implicit val environment: Environment[HatApiAuthEnvironment] =
    FakeEnvironment[HatApiAuthEnvironment](
      Seq(owner.loginInfo -> owner),
      hatServer
    )

  "The `applicationStatus` parameterless method" should "List all available applications" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result  = service.applicationStatus()

    val apps = Await.result(result, 10.seconds)

    apps.length must equal(8)
    apps.find(_.application.id == notablesApp.id) must be('defined)
    apps.find(_.application.id == notablesAppDebitless.id) must be('defined)
    apps.find(_.application.id == notablesAppIncompatible.id) must be('defined)
  }

  it should "Include setup applications" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      _ <- service.setup(HatApplication(notablesApp, setup = false, enabled = false, active = false, None, None, None))
      apps <- service.applicationStatus()
    } yield apps

    val apps = Await.result(result, 10.seconds)
    apps.length must equal(8)
    apps.find(_.application.id == notablesAppDebitless.id) must be('defined)
    apps.find(_.application.id == notablesAppIncompatible.id) must be('defined)
    val setupApp = apps.find(_.application.id == notablesApp.id)
    setupApp must be('defined)
    setupApp.get.setup must be(true)
  }

  "The `applicationStatus` method" should "Provide status for a specific application" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesApp.id)
    } yield app

    val app = Await.result(result, 10.seconds)
    app must be('defined)
    app.get.application.id must equal(notablesApp.id)
  }

  it should "Return `None` when application is not found by ID" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus("randomid")
    } yield app

    val app = Await.result(result, 10.seconds)
    app must not be 'defined
  }

  it should "Return `active=false` status for Internal status check apps that are not setup" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesApp.id)
    } yield app

    val app = Await.result(result, 10.seconds)
    app must be('defined)
    app.get.active must equal(false)
  }

  it should "Return `active=true` status and most recent data timestamp for active app" in {
    val service     = application.injector.instanceOf[ApplicationsService]
    val dataService = application.injector.instanceOf[RichDataService]
    val result = for {
      app <- service.applicationStatus(notablesApp.id)
      _ <- service.setup(app.get)
      _ <- dataService.saveData(
             owner.userId,
             Seq(
               EndpointData(notablesApp.status.recentDataCheckEndpoint.get,
                            None,
                            None,
                            None,
                            JsObject(Map("test" -> JsString("test"))),
                            None
               )
             ),
             skipErrors = true
           )
      app <- service.applicationStatus(notablesApp.id, bustCache = true)
    } yield app

    val app = Await.result(result, 10.seconds)
    app must be('defined)
    app.get.setup must equal(true)
    app.get.needsUpdating must ===(false)
    // app.get.mostRecentData must beSome[DateTime]
  }

  it should "Return `active=false` status for External status check apps that are setup but respond with wrong status" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesAppExternalFailing.id)
      _ <- service.setup(app.get)
      setup <- service.applicationStatus(notablesAppExternalFailing.id)
    } yield setup

    val setup = Await.result(result, 10.seconds)
    setup must be('defined)
    setup.get.setup must equal(true)
    setup.get.active must equal(false)
  }

  it should "Return `active=true` status for External status check apps that are setup" in {
    val service = application.injector.instanceOf[ApplicationsService]

    val result = for {
      app <- service.applicationStatus(notablesAppExternal.id)
      _ <- service.setup(app.get)
      setup <- service.applicationStatus(notablesAppExternal.id)
    } yield setup

    val setup = Await.result(result, 10.seconds)
    setup must be('defined)
    setup.get.setup must equal(true)
    setup.get.active must equal(true)
  }

  it should "Return `active=false` status for apps where current version is not compatible with one setup" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      _ <- service.setup(
             HatApplication(notablesAppIncompatible, setup = false, enabled = false, active = false, None, None, None)
           )
      app <- service.applicationStatus(notablesAppIncompatibleUpdated.id)
    } yield app

    val app = Await.result(result, 10.seconds)
    app must be('defined)
    app.get.setup must equal(true)
    app.get.needsUpdating must ===(true)
  }

  it should "Return `active=false` status for apps where data debit has been disabled" in {
    val service          = application.injector.instanceOf[ApplicationsService]
    val dataDebitService = application.injector.instanceOf[DataDebitService]
    val cache            = application.injector.instanceOf[AsyncCacheApi]
    val result = for {
      app <- service.applicationStatus(notablesApp.id)
      _ <- service.setup(app.get)(hatServer, owner, fakeRequest)
      _ <- dataDebitService.dataDebitDisable(app.get.application.dataDebitId.get, cancelAtPeriodEnd = false)
      _ <- cache.remove(
             service.appCacheKey(app.get.application.id)
           ) //cache.remove(s"apps:${hatServer.domain}:${app.get.application.id}")
      _ <- cache.get(service.appCacheKey(app.get.application.id))
      setup <- service.applicationStatus(app.get.application.id)
    } yield setup

    val setup = Await.result(result, 10.seconds)
    setup must be('defined)
    setup.get.setup must equal(true)
    setup.get.active must equal(false)
  }

  "The `setup` method" should "Enable an application and update its status as well as enable data debit if set up" in {
    val service          = application.injector.instanceOf[ApplicationsService]
    val dataDebitService = application.injector.instanceOf[DataDebitService]
    val result = for {
      app <- service.applicationStatus(notablesApp.id)
      setup <- service.setup(app.get)
      dd <- dataDebitService.dataDebit(notablesApp.dataDebitId.get)
      _ <- dataDebitService.dataDebit(app.get.application.dataDebitId.get)
    } yield (setup, dd)

    val (setup, dd) = Await.result(result, 10.seconds)
    setup.active must equal(true)
    dd must be('defined)
    dd.get.activePermissions must be('defined)
    dd.get.activePermissions.get.bundle.name must equal(notablesApp.permissions.dataRequired.get.bundle.name)
  }

  it should "Enable an application and update its status with no data debit required" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesAppDebitless.id)
      setup <- service.setup(app.get)
    } yield setup

    val setup = Await.result(result, 10.seconds)
    setup.active must equal(true)
  }

  it should "Return failure for a made-up Application Information" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      setup <- service.setup(HatApplication(notablesAppMissing, true, true, true, None, None, None))
    } yield setup

    //val thrown = the[HatApplicationSetupException] thrownBy (Await.result(result, 10.seconds))
    //thrown.message should equal("String index out of range: -1")
    fail()
  }

  "Application `setup` method for applications with dependencies" should "Enable plug dependencies" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesAppDebitlessWithPlugDependency.id)
      setup <- service.setup(app.get)
      dependency <- service.applicationStatus(plugApp.id)
    } yield (setup, dependency)

    val (setup, dependency) = Await.result(result, 10.seconds)
    setup.active must equal(true)
    setup.enabled must equal(true)
    setup.dependenciesEnabled must ===(true)
    dependency.get.enabled must equal(true)
  }

  it should "Return partial success for application with invalid dependencies" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesAppDebitlessWithInvalidDependency.id)
      setup <- service.setup(app.get)
    } yield setup

    val setup = Await.result(result, 10.seconds)
    setup.active must equal(true)
    setup.enabled must equal(true)
    setup.dependenciesEnabled must ===(false)

  }

  "The `disable` method" should "Disable an application with associated data debit" in {
    val service          = application.injector.instanceOf[ApplicationsService]
    val dataDebitService = application.injector.instanceOf[DataDebitService]
    val result = for {
      app <- service.applicationStatus(notablesApp.id)
      _ <- service.setup(app.get)
      setup <- service.disable(app.get)
      dd <- dataDebitService.dataDebit(app.get.application.dataDebitId.get)
    } yield (setup, dd)

    val (setup, dd) = Await.result(result, 10.seconds)
    setup.active must equal(false)
    dd must be('defined)
    dd.get.activePermissions must not be 'defined
  }

  it should "Disable an application without a data debit" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesAppDebitless.id)
      _ <- service.setup(app.get)
      setup <- service.disable(app.get)
    } yield setup.active must equal(false)

    Await.result(result, 20.seconds)
  }

  it should "Return failure for a made-up Application Information" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      setup <- service.disable(HatApplication(notablesAppMissing, true, true, true, None, None, None))
    } yield setup

    //result must throwA[RuntimeException].await(1, 20.seconds)
    fail()
  }

  "The `applicationToken` method" should "Create a token that includes application and its version among custom claims" in {
    import org.scalatest.TryValues._

    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      token <- service.applicationToken(owner, notablesApp)
    } yield {
      token.accessToken must not equal("")
      val encoder      = new Base64AuthenticatorEncoder()
      val settings     = JWTRS256AuthenticatorSettings("X-Auth-Token", None, "hat.org", Some(3.days), 3.days)
      val unserialized = JWTRS256Authenticator.unserialize(token.accessToken, encoder, settings)

      unserialized match {
        case Success(_value@_) => true
        case Failure(_exception@_) => fail()
      }

      (unserialized.get.customClaims.get \ "application").get must equal(JsString(notablesApp.id))
      (unserialized.get.customClaims.get \ "applicationVersion").get must equal(JsString(
        notablesApp.info.version.toString
      ))
    }
    Await.result(result, 20.seconds)
  }

  // "The `ApplicationStatusCheckService` `status` method" should "Return `true` for internal status checks" in {
  //   withMockWsClient { client =>
  //     val service = new ApplicationStatusCheckService(client)(remoteEC)
  //     service.status(ApplicationStatus
  //                   .Internal(Version("1.0.0"), None, None, None, DateTime.now()),
  //                 "token"
  //     )
  //         .map { result =>
  //           result must beTrue
  //         }
  //         .await(1, 10.seconds)
  //     }
  //   }
  

  //   "Return `true` for external check with matching status" in {
  //     withMockWsClient { client =>
  //       val service = new ApplicationStatusCheckService(client)(remoteEC)
  //       service
  //         .status(ApplicationStatus.External(Version("1.0.0"), "/status", 200, None, None, None, DateTime.now()),
  //                 "token"
  //         )
  //         .map { result =>
  //           result must beTrue
  //         }
  //         .await(1, 10.seconds)
  //     }
  //   }

  //   "Return `false` for external check with non-matching status" in {
  //     withMockWsClient { client =>
  //       val service = new ApplicationStatusCheckService(client)(remoteEC)
  //       service
  //         .status(ApplicationStatus.External(Version("1.0.0"), "/failing", 200, None, None, None, DateTime.now()),
  //                 "token"
  //         )
  //         .map { result =>
  //           result must beFalse
  //         }
  //         .await(1, 10.seconds)
  //     }
  //   }

  "JoinContract" should "not run unless the application template is a Contract" in {
    val service = application.injector.instanceOf[ApplicationsService]

    val result = for {
      contractApp <- service.joinContract(fakeContract, "hatName")
      notablesApp <- service.joinContract(notablesApp, "hatName")
    } yield {
      println(contractApp)
      println(notablesApp)
      notablesApp must equal(Done)
      //contractApp must beLeft(ServiceRespondedWithFailure("The Adjudicator Service responded with an error: Internal Server Error"))
    }

    Await.result(result, 20.seconds)
  }

  // Commented until I figure out how to Mock it.
  //    "Adding a Contract should succeed" in {
  //      val service = application.injector.instanceOf[ApplicationsService]
  //
  //      val result = for {
  //        _ <- service.setup(
  //          HatApplication(
  //            fakeContract,
  //            setup = false,
  //            enabled = false,
  //            active = false,
  //            None,
  //            None,
  //            None))
  //        apps <- service.applicationStatus()
  //      } yield {
  //        apps.length must be equalTo 8
  //        val setupApp = apps.find(_.application.id == notablesApp.id)
  //        setupApp must beSome
  //        setupApp.get.setup must beTrue
  //      }
  //
  //      result await (1, 20.seconds)
  //    }
}
