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

import com.mohiva.play.silhouette.api.crypto.Base64AuthenticatorEncoder
import com.mohiva.play.silhouette.impl.authenticators.{ JWTRS256Authenticator, JWTRS256AuthenticatorSettings }
import org.hatdex.hat.api.models.EndpointData
import org.hatdex.hat.api.models.applications.{ ApplicationStatus, HatApplication, Version }
import org.hatdex.hat.api.service.applications.ApplicationExceptions.{
  HatApplicationDependencyException,
  HatApplicationSetupException
}
import org.hatdex.hat.api.service.richData.{ DataDebitService, RichDataService }
import org.hatdex.hat.utils.AdjudicatorRequestTypes.JoinContractRequestFailure.ServiceRespondedWithFailure
import org.joda.time.DateTime
import play.api.Logger
import play.api.cache.AsyncCacheApi
import play.api.libs.json._
import akka.Done

import scala.concurrent.Await
import scala.concurrent.duration._
import io.dataswift.test.common.BaseSpec
import org.scalatest.{ BeforeAndAfterEach, BeforeAndAfterAll }
import play.api.test.Helpers
import play.api.test.Helpers._

class ApplicationsServiceSpec
    extends BaseSpec
    with BeforeAndAfterEach
    with BeforeAndAfterAll
    with ApplicationsServiceContext {

  import scala.concurrent.ExecutionContext.Implicits.global
  val logger = Logger(this.getClass)

  override def beforeAll: Unit =
    Await.result(databaseReady, 60.seconds)

  override def afterAll() =
    container.stop()


  override def beforeEach: Unit = {
    import org.hatdex.hat.dal.Tables
    import org.hatdex.libs.dal.HATPostgresProfile.api._

    val action = DBIO.seq(
      Tables.DataDebitPermissions.delete,
      Tables.DataBundles.filter(_.bundleId like "notables%").delete,
      Tables.DataDebit.delete,
      Tables.ApplicationStatus.delete
    )

    val cache = application.injector.instanceOf[AsyncCacheApi]
    cache.removeAll()

    Await.result(db.run(action), 60.seconds)
  }

  "The `applicationStatus` parameterless method" should "List all available applications" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      apps <- service.applicationStatus()
    } yield {
      apps.length must equal(8)
      apps.find(_.application.id == notablesApp.id) must not be empty
      apps.find(_.application.id == notablesAppDebitless.id) must not be empty
      apps.find(_.application.id == notablesAppIncompatible.id) must not be empty
    }
    Await.result(result, 20.seconds)
  }

  it should "Include setup applications" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {

      _ <- service.setup(HatApplication(notablesApp, setup = false, enabled = false, active = false, None, None, None))
      apps <- service.applicationStatus()
    } yield {
      apps.length must equal(8)
      apps.find(_.application.id == notablesAppDebitless.id) must not be empty
      apps.find(_.application.id == notablesAppIncompatible.id) must not be empty
      val setupApp = apps.find(_.application.id == notablesApp.id)
      setupApp must not be empty
      setupApp.get.setup must equal(true)
    }
    Await.result(result, 20.seconds)
  }

  "The `applicationStatus` method" should "Provide status for a specific application" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesApp.id)
    } yield {
      app must not be empty
      app.get.application.id must equal(notablesApp.id)
    }
    Await.result(result, 20.seconds)

  }

  it should "Return `None` when application is not found by ID" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus("randomid")
    } yield app
    val app = Await.result(result, 20.seconds)
    app must equal(None)
  }

  it should "Return `active=false` status for Internal status check apps that are not setup" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesApp.id)
    } yield {
      app must not be empty
      // ???
      app.get.active must equal(false)
    }
    Await.result(result, 20.seconds)
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
    } yield {
      app must not be empty
      app.get.setup must equal(true)
      app.get.needsUpdating === false
      // TODO: what is the matcher for this?
      //app.get.mostRecentData must beSome[DateTime]
    }
    Await.result(result, 10.seconds)
  }

  it should "Return `active=false` status for External status check apps that are setup but respond with wrong status" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesAppExternalFailing.id)
      appSetupResponse <- service.setup(app.get)
      setup <- service.applicationStatus(notablesAppExternalFailing.id)
    } yield {
      setup must not be empty
      appSetupResponse.setup must equal(true)
      setup.get.setup must equal(true)
      setup.get.active must equal(false)
    }
    Await.result(result, 10.seconds)
  }

  it should "Return `active=true` status for External status check apps that are setup" in {
    val service = application.injector.instanceOf[ApplicationsService]

    val result = for {
      app <- service.applicationStatus(notablesAppExternal.id)
      _ <- service.setup(app.get)
      setup <- service.applicationStatus(notablesAppExternal.id)
    } yield {
      setup must not be empty
      setup.get.setup must equal(true)
      setup.get.active must equal(true)
    }

    Await.result(result, 10.seconds)
  }

  it should "Return `active=false` status for apps where current version is not compatible with one setup" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      _ <- service.setup(
             HatApplication(notablesAppIncompatible, setup = false, enabled = false, active = false, None, None, None)
           )
      app <- service.applicationStatus(notablesAppIncompatibleUpdated.id)
    } yield {
      app must not be empty
      app.get.setup must equal(true)
      app.get.needsUpdating === true
    }
    Await.result(result, 10.seconds)
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
    } yield {
      setup must not be empty
      setup.get.setup must equal(true)
      setup.get.active must equal(false)
    }
    Await.result(result, 10.seconds)
  }

  "The `setup` method" should "Enable an application and update its status as well as enable data debit if set up" in {
    val service          = application.injector.instanceOf[ApplicationsService]
    val dataDebitService = application.injector.instanceOf[DataDebitService]
    val result = for {
      app <- service.applicationStatus(notablesApp.id)
      setup <- service.setup(app.get)
      dd <- dataDebitService.dataDebit(notablesApp.dataDebitId.get)
      _ <- dataDebitService.dataDebit(app.get.application.dataDebitId.get)
    } yield {
      setup.active must equal(true)
      dd must not be empty
      dd.get.activePermissions must not be empty
      dd.get.activePermissions.get.bundle.name must equal(notablesApp.permissions.dataRequired.get.bundle.name)
    }
    Await.result(result, 10.seconds)
  }

  it should "Enable an application and update its status with no data debit required" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesAppDebitless.id)
      setup <- service.setup(app.get)
    } yield setup.active must equal(true)

    Await.result(result, 10.seconds)
  }

  it should "Return failure for a made-up Application Information" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      setup <- service.setup(HatApplication(notablesAppMissing, true, true, true, None, None, None))
    } yield setup

    an[HatApplicationSetupException] should be thrownBy Await.result(result, 10.seconds)
  }

  "Application `setup` method for applications with dependencies" should "Enable plug dependencies" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesAppDebitlessWithPlugDependency.id)
      setup <- service.setup(app.get)
      dependency <- service.applicationStatus(plugApp.id)
    } yield {
      setup.active must equal(true)
      setup.enabled must equal(true)
      setup.dependenciesEnabled must not be empty
      dependency.get.enabled === true
    }

    Await.result(result, 10.seconds)
  }

  it should "Return partial success for application with invalid dependencies" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesAppDebitlessWithInvalidDependency.id)
      setup <- service.setup(app.get)
    } yield {
      setup.active must equal(true)
      setup.enabled must equal(true)
      setup.dependenciesEnabled === false
    }

    Await.result(result, 10.seconds)
  }

  "The `disable` method" should "Disable an application with associated data debit" in {
    val service          = application.injector.instanceOf[ApplicationsService]
    val dataDebitService = application.injector.instanceOf[DataDebitService]
    val result = for {
      app <- service.applicationStatus(notablesApp.id)
      _ <- service.setup(app.get)
      setup <- service.disable(app.get)
      dd <- dataDebitService.dataDebit(app.get.application.dataDebitId.get)
    } yield {
      setup.active must equal(false)
      dd must not be empty
      dd.get.activePermissions must equal(None)
    }

    Await.result(result, 10.seconds)
  }

  it should "Disable an application without a data debit" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      app <- service.applicationStatus(notablesAppDebitless.id)
      _ <- service.setup(app.get)
      setup <- service.disable(app.get)
    } yield setup.active must equal(true)

    Await.result(result, 10.seconds)
  }

  it should "Return failure for a made-up Application Information" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      setup <- service.disable(HatApplication(notablesAppMissing, true, true, true, None, None, None))
    } yield setup

    an[RuntimeException] should be thrownBy Await.result(result, 10.seconds)
  }

  "The `applicationToken` method" should "Create a token that includes application and its version among custom claims" in {
    val service = application.injector.instanceOf[ApplicationsService]
    val result = for {
      token <- service.applicationToken(owner, notablesApp)
    } yield {
      token.accessToken must not equal("")
      val encoder      = new Base64AuthenticatorEncoder()
      val settings     = JWTRS256AuthenticatorSettings("X-Auth-Token", None, "hat.org", Some(3.days), 3.days)
      val unserialized = JWTRS256Authenticator.unserialize(token.accessToken, encoder, settings)

      // TODO: How do I match this?
      //unserialized must beSuccessfulTry
      (unserialized.get.customClaims.get \ "application").get must equal(JsString(notablesApp.id))
      (unserialized.get.customClaims.get \ "applicationVersion").get must equal(JsString(
        notablesApp.info.version.toString
      ))
    }

    Await.result(result, 10.seconds)

  }

  "The `ApplicationStatusCheckService` `status` method" should "Return `true` for internal status checks" in {
      withMockWsClient { client =>
        val service = new ApplicationStatusCheckService(client)(remoteEC)
        val result = service
          .status(ApplicationStatus
                    .Internal(Version("1.0.0"), None, None, None, DateTime.now()),
                  "token"
          )
          .map { result =>
            result must equal(true)
          }
          Await.result(result, 10.seconds)
      }
    }
    

    it should "Return `true` for external check with matching status" in {
      withMockWsClient { client =>
        val service = new ApplicationStatusCheckService(client)(remoteEC)
        val result = service
          .status(ApplicationStatus.External(Version("1.0.0"), "/status", 200, None, None, None, DateTime.now()),
                  "token"
          )
          .map { result =>
            result must equal(true)
          }
          Await.result(result, 10.seconds)
      }
    }

   it should  "Return `false` for external check with non-matching status" in {
      withMockWsClient { client =>
        val service = new ApplicationStatusCheckService(client)(remoteEC)
        val result = service
          .status(ApplicationStatus.External(Version("1.0.0"), "/failing", 200, None, None, None, DateTime.now()),
                  "token"
          )
          .map { result =>
            result must equal(false)
          }
          Await.result(result, 10.seconds)
      }
    }

    "JoinContract" should "not run unless the application template is a Contract" in {
      val service = application.injector.instanceOf[ApplicationsService]

      val result = for {
        _ <- service.joinContract(fakeContract, "hatName")
        notablesApp <- service.joinContract(notablesApp, "hatName")
      } yield {
        notablesApp must equal(Done)
        //contractApp must beLeft(ServiceRespondedWithFailure("The Adjudicator Service responded with an error: Internal Server Error"))
      }
      Await.result(result, 10.seconds)
    }

  // Commented until I figure out how to Mock it.
  //    "Adding a Contract should succeed" in {
  //      val service = application.injector.instanceOf[ApplicationsService]
  
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
  //        apps.length must be equal 8
  //        val setupApp = apps.find(_.application.id == notablesApp.id)
  //        setupApp must not be empty
  //        setupApp.get.setup must beTrue
  //      }
  
  //      result await (1, 20.seconds)
  //    }
  }
  
