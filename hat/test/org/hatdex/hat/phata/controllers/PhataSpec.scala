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

package org.hatdex.hat.phata.controllers

import com.mohiva.play.silhouette.test._
import org.hatdex.hat.api.models.EndpointData
import org.hatdex.hat.api.service.richData.RichDataService
import play.api.Logger
import play.api.libs.json.Json
import play.api.test.{ FakeRequest, Helpers }
import com.dimafeng.testcontainers.{ ForAllTestContainer, PostgreSQLContainer }
import play.api.{ Logger, Application => PlayApplication }
import org.hatdex.hat.helpers.{ ContainerUtils }
import org.hatdex.libs.dal.HATPostgresProfile.backend.Database
import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, HatServer }
import play.api.Configuration
import com.atlassian.jwt.core.keys.KeyUtils
import java.io.StringReader
import play.api.inject.guice.GuiceApplicationBuilder
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.api.service.UsersService
import play.api.test.Helpers._
import play.api.cache.AsyncCacheApi
import scala.concurrent.{ Await, Future }
import scala.concurrent.duration._
import com.mohiva.play.silhouette.api.Environment
import org.hatdex.hat.authentication.HatApiAuthEnvironment
import akka.stream.Materializer
import io.dataswift.test.common.BaseSpec
import org.hatdex.hat.fixtures.PlayControllerFixture
import com.mohiva.play.silhouette.api.LoginInfo

class PhataSpec extends BaseSpec with ContainerUtils with PhataContext with ForAllTestContainer {

  import scala.concurrent.ExecutionContext.Implicits.global

  override val container = PostgreSQLContainer()
  container.start()
  val conf = containerToConfig(container)

  val hatAddress        = "hat.hubofallthings.net"
  val logger            = Logger(this.getClass)
  private val keyUtils  = new KeyUtils()
  private val hatConfig = conf.get[Configuration](s"hat.$hatAddress")

  implicit lazy val materializer: Materializer = application.materializer

  implicit val db: Database = Database.forURL(
    url = container.jdbcUrl,
    user = container.username,
    password = container.password
  )

  implicit val hatServer: HatServer = HatServer(
    hatAddress,
    "hat",
    "user@hat.org",
    keyUtils.readRsaPrivateKeyFromPem(new StringReader(hatConfig.get[String]("privateKey"))),
    keyUtils.readRsaPublicKeyFromPem(new StringReader(hatConfig.get[String]("publicKey"))),
    db
  )

  implicit val application: PlayApplication = new GuiceApplicationBuilder()
    .configure(conf)
    .build()

  Await.result(databaseReady(db, conf), 60.seconds)

  val owner = new HatUser(userId = java.util.UUID.randomUUID(),
                          email = "hat@example.com",
                          pass = None,
                          name = "hat",
                          roles = Seq.empty,
                          enabled = true
  )

  val userService = application.injector.instanceOf[UsersService]
  userService.saveUser(owner)

  implicit val env: Environment[HatApiAuthEnvironment] =
    FakeEnvironment[HatApiAuthEnvironment](Seq(owner.loginInfo -> owner), hatServer)

  "The `profile` method" should "Return bundle data with profile information" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller  = application.injector.instanceOf[Phata]
    val dataService = application.injector.instanceOf[RichDataService]

    val data = List(
      EndpointData("rumpel/notablesv1", None, None, None, samplePublicNotable, None),
      EndpointData("rumpel/notablesv1", None, None, None, samplePrivateNotable, None),
      EndpointData("rumpel/notablesv1", None, None, None, sampleSocialNotable, None)
    )

    val result = for {
      _ <- dataService.saveData(owner.userId, data)
      response <- Helpers.call(controller.profile, request)
    } yield response

    val r = Await.result(result, 10.seconds)
    r.header.status must equal(OK)
    //val phataData = r.body.as[Map[String, Seq[EndpointData]]]
    // phataData.get("notables") should be('defined)
    // phataData("notables").length should equal(1)
  }

  it should "return OK if authenticator for matching identity" in new PhataContext {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[Phata]
    val result     = Helpers.call(controller.profile, request)

    val r = Await.result(result, 10.seconds)
    r.header.status must equal(OK)
    contentAsJson(result).toString.indexOf("notables") must be > 0
  }

  // Convert to this
  // private class Fixture extends PlayControllerFixture {
  //   val controller  = application.injector.instanceOf[Phata]
  //   val dataService = application.injector.instanceOf[RichDataService]
  //   val cache       = application.injector.instanceOf[AsyncCacheApi]
  //   val memcached   = application.injector.instanceOf[MemcachedModule]
  // }

}

trait PhataContext {
  val samplePublicNotable = Json.parse("""
      |{
      |    "kind": "note",
      |    "author":
      |    {
      |        "phata": "testing.hubat.net"
      |    },
      |    "shared": true,
      |    "message": "public message",
      |    "shared_on": "phata",
      |    "created_time": "2017-10-18T15:32:43+01:00",
      |    "public_until": "",
      |    "updated_time": "2017-10-23T18:29:59+01:00"
      |}
    """.stripMargin)

  val samplePrivateNotable = Json.parse("""
      |{
      |    "kind": "note",
      |    "author":
      |    {
      |        "phata": "testing.hubat.net"
      |    },
      |    "shared": false,
      |    "message": "private message",
      |    "shared_on": "marketsquare",
      |    "created_time": "2017-10-18T15:32:43+01:00",
      |    "public_until": "",
      |    "updated_time": "2017-10-23T18:29:59+01:00"
      |}
    """.stripMargin)

  val sampleSocialNotable = Json.parse("""
      |{
      |    "kind": "note",
      |    "author":
      |    {
      |        "phata": "testing.hubat.net"
      |    },
      |    "shared": true,
      |    "message": "social message",
      |    "shared_on": "facebook,twitter",
      |    "created_time": "2017-10-18T15:32:43+01:00",
      |    "public_until": "",
      |    "updated_time": "2017-10-23T18:29:59+01:00"
      |}
    """.stripMargin)
}
