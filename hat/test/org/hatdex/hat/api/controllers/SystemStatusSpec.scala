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
 * 11 / 2017
 */

package org.hatdex.hat.api.controllers

import com.mohiva.play.silhouette.test._
import org.hatdex.hat.api.json.HatJsonFormats
import org.hatdex.hat.api.models.{ HatStatus, StatusKind }
import play.api.Logger
import play.api.test.{ FakeRequest }
import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, HatServer }
import scala.concurrent.duration._
import scala.concurrent.{ Await }
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
import org.hatdex.hat.api.service.UsersService
import play.api.test.Helpers

class SystemStatusSpec
    extends AnyFlatSpec
    with Matchers
    with ContractDataContext
    with HatJsonFormats
    with ContainerUtils
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

  implicit val hatServer: HatServer = HatServer(
    hatAddress,
    "hat",
    "user@hat.org",
    keyUtils.readRsaPrivateKeyFromPem(new StringReader(hatConfig.get[String]("privateKey"))),
    keyUtils.readRsaPublicKeyFromPem(new StringReader(hatConfig.get[String]("publicKey"))),
    db
  )

  val owner = new HatUser(userId = java.util.UUID.randomUUID(),
                          email = "user@hat.org",
                          pass = Some("$2a$06$QprGa33XAF7w8BjlnKYb3OfWNZOuTdzqKeEsF7BZUfbiTNemUW/n."),
                          name = "hat",
                          roles = Seq(Owner(), DSPlatform()),
                          enabled = true
  )

  val application: PlayApplication = new GuiceApplicationBuilder()
    .configure(FakeHatConfiguration.config)
    .build()

  println(owner.loginInfo)

  implicit lazy val materializer: Materializer = application.materializer

  // I need a before
  val conf = containerToConfig(container)
  Await.result(databaseReady(db, conf), 60.seconds)

  implicit val environment: Environment[HatApiAuthEnvironment] =
    FakeEnvironment[HatApiAuthEnvironment](Seq(owner.loginInfo -> owner), hatServer)

  val userService = application.injector.instanceOf[UsersService]
  userService.saveUser(owner)

  /*
  "The `update` method" should "Return success response after updating HAT database" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")

    val controller = application.injector.instanceOf[SystemStatus]
    val req        = Helpers.call(controller.update, request)

    val response = Await.result(req, 600.seconds)
    response.header.status should equal(200)
    //(contentAsJson(response.body) \ "message").as[String] should equal("Database updated")
  }

  "The `status` method" should "Return current utilisation" in {
    implicit val environment: Environment[HatApiAuthEnvironment] =
      FakeEnvironment[HatApiAuthEnvironment](Seq(owner.loginInfo -> owner), hatServer)

    val request = FakeRequest("GET", hatUrl)
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[SystemStatus]
    val req        = Helpers.call(controller.status, request)
    println("----")
    println(contentAsJson(req))
    println("----")

    val stats = contentAsJson(req).as[List[HatStatus]]
    stats.length should be > 0
    stats.find(_.title == "Previous Login").get.kind should equal(StatusKind.Text("Never", None))
    stats.find(_.title == "Owner Email").get.kind should equal(StatusKind.Text("user@hat.org", None))
    stats.find(_.title == "Database Storage").get.kind shouldBe a[StatusKind.Numeric]
    stats.find(_.title == "File Storage").get.kind shouldBe a[StatusKind.Numeric]
    stats.find(_.title == "Database Storage Used").get.kind shouldBe a[StatusKind.Numeric]
    stats.find(_.title == "File Storage Used").get.kind shouldBe a[StatusKind.Numeric]
    stats.find(_.title == "Database Storage Used Share").get.kind shouldBe a[StatusKind.Numeric]
    stats.find(_.title == "File Storage Used Share").get.kind shouldBe a[StatusKind.Numeric]
  }
   */

  /*
  it should "Return last login information when present" in {
    val authRequest = FakeRequest("GET", hatUrl)
      .withHeaders("username" -> "hat", "password" -> "pa55w0rd")

    val authController = application.injector.instanceOf[Authentication]

    val request = FakeRequest("GET", hatUrl)
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[SystemStatus]

    println("11111")

    val result = for {
      //_ <- authController.accessToken().apply(authRequest)
      // login twice - the second login is considered "current", not previous
      r <- Helpers.call(authController.accessToken(), authRequest)
      //r <- controller.status().apply(request)
    } yield r

    status(result) should equal(OK)
    val stats = contentAsJson(result).as[List[HatStatus]]

    stats.length should be > 0
    stats.find(_.title == "Previous Login").get.kind should equal(StatusKind.Text("moments ago", None))
  }
   */
}
