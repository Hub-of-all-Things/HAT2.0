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

package org.hatdex.hat.api.service.richData

import org.hatdex.hat.api.models._
import org.joda.time.LocalDateTime
import play.api.Logger
import org.hatdex.libs.dal.HATPostgresProfile.backend.Database

import org.scalatest._
import matchers.should._
import flatspec._
import com.dimafeng.testcontainers.{ ForAllTestContainer, PostgreSQLContainer }

import scala.concurrent.Await
import scala.concurrent.duration._
import play.api.Configuration
import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, HatServer }
import scala.concurrent.{ Await, Future }
import com.atlassian.jwt.core.keys.KeyUtils
import java.io.StringReader
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.{ Logger, Application => PlayApplication }
import org.hatdex.hat.helpers.{ ContainerUtils }
import org.hatdex.hat.authentication.models.HatUser
import scala.util.Random
import org.hatdex.hat.api.service.UsersService

class DataDebitContractServiceSpec
    extends AnyFlatSpec
    with Matchers
    //with DataDebitServiceSpecContext
    with DataDebitContractServiceContext
    with ContainerUtils
    with ForAllTestContainer {

  // Ephemeral PG Container for this test suite
  override val container = PostgreSQLContainer()
  container.start()

  val hatAddress            = "hat.hubofallthings.net"
  val logger                = Logger(this.getClass)
  private val configuration = Configuration.from(FakeHatConfiguration.config)
  private val hatConfig     = configuration.get[Configuration](s"hat.$hatAddress")
  private val keyUtils      = new KeyUtils()

  implicit val application: PlayApplication = new GuiceApplicationBuilder()
    .configure(FakeHatConfiguration.config)
    .build()

  implicit val db: Database = Database.forURL(
    url = container.jdbcUrl,
    user = container.username,
    password = container.password
  )

  val owner = new HatUser(userId = java.util.UUID.randomUUID(),
                          email = "hat@example.com",
                          pass = None,
                          name = "hat",
                          roles = Seq.empty,
                          enabled = true
  )

  implicit val hatServer: HatServer = HatServer(
    hatAddress,
    "hat",
    "user@hat.org",
    keyUtils.readRsaPrivateKeyFromPem(new StringReader(hatConfig.get[String]("privateKey"))),
    keyUtils.readRsaPublicKeyFromPem(new StringReader(hatConfig.get[String]("publicKey"))),
    db
  )

  import scala.concurrent.ExecutionContext.Implicits.global

  // I need a before
  val conf = containerToConfig(container)
  Await.result(databaseReady(db, conf), 60.seconds)

  val userService = application.injector.instanceOf[UsersService]
  userService.saveUser(owner)

  "The `createDataDebit` method" should "Save a data debit" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val saved   = service.createDataDebit("testdd", testDataDebitRequest, owner.userId)

    val debit = Await.result(saved, 10.seconds)
    debit.client.email should equal(owner.email)
    debit.dataDebitKey should equal("testdd")
    debit.bundles.length should equal(1)
    debit.bundles.head.rolling should be(false)
    debit.bundles.head.enabled should be(false)
  }

  it should "Throw an error when a duplicate data debit is getting saved" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val saved = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      saved <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
    } yield saved

    saved
      .flatMap { result =>
        result match {
          // This should fail with an exception, so return a fail() on success.
          case _ => fail()
        }
      }
      .recover { failedResult =>
        failedResult match {
          case (_: Exception) => Future.successful(true)
        }
      }

  }

  "The `dataDebit` method" should "Return a data debit by ID" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val ddKey1  = Random.alphanumeric.take(10).mkString
    val saved = for {
      _ <- service.createDataDebit(ddKey1, newTestDataDebitRequest(ddKey1), owner.userId)
      saved <- service.dataDebit(ddKey1)
    } yield saved

    val maybeDebit = Await.result(saved, 10.seconds)
    maybeDebit should be('defined)
    val debit = maybeDebit.get
    debit.client.email should equal(owner.email)
    debit.dataDebitKey should equal(ddKey1)
    debit.bundles.length should equal(1)
    debit.bundles.head.enabled should be(false)
  }

  it should "Return None when data debit doesn't exist" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val ddKey1  = Random.alphanumeric.take(20).mkString

    val saved = for {
      saved <- service.dataDebit(ddKey1)
    } yield saved

    val maybeDebit = Await.result(saved, 10.seconds)
    maybeDebit should not be 'defined
  }

  "The `dataDebitEnable` method" should "Enable an existing data debit" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val ddKey1  = Random.alphanumeric.take(10).mkString
    val saved = for {
      _ <- service.createDataDebit(ddKey1, newTestDataDebitRequest(ddKey1), owner.userId)
      _ <- service.dataDebitEnableBundle(ddKey1, None)
      saved <- service.dataDebit(ddKey1)
    } yield saved

    val maybeDebit = Await.result(saved, 10.seconds)
    maybeDebit should be('defined)
    val debit = maybeDebit.get
    debit.client.email should equal(owner.email)
    debit.dataDebitKey should equal(ddKey1)
    debit.bundles.length should equal(1)
    debit.bundles.head.enabled should be(true)
    debit.activeBundle should be('defined)
  }

  it should "Enable a data debit after a few iterations of bundle adjustments" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val ddKey1  = Random.alphanumeric.take(10).mkString
    val ddKey2  = Random.alphanumeric.take(10).mkString
    val dd1     = newTestDataDebitRequest(ddKey1)
    val dd2     = newTestDataDebitRequest(ddKey2)
    val saved = for {
      _ <- service.createDataDebit(ddKey1, dd1, owner.userId)
      _ <- service.updateDataDebitBundle(ddKey1, dd2, owner.userId)
      _ <- service.dataDebitEnableBundle(ddKey1, Some(dd2.bundle.name))
      saved <- service.dataDebit(ddKey1)
    } yield saved

    val maybeDebit = Await.result(saved, 10.seconds)
    maybeDebit should be('defined)
    val debit = maybeDebit.get
    debit.client.email should equal(owner.email)
    debit.dataDebitKey should equal(ddKey1)
    debit.bundles.length should equal(2)
    debit.activeBundle should be('defined)
    debit.activeBundle.get.bundle.name should equal(dd2.bundle.name)
    debit.bundles.exists(_.enabled == false) should be(true)
  }

  "The `dataDebitDisable` method" should "Disable all bundles linked to a data debit" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val ddKey1  = Random.alphanumeric.take(10).mkString
    val ddKey2  = Random.alphanumeric.take(10).mkString
    val dd1     = newTestDataDebitRequest(ddKey1)
    val dd2     = newTestDataDebitRequestUpdate(ddKey2)

    val saved = for {
      _ <- service.createDataDebit(ddKey1, dd1, owner.userId)
      _ <- service.dataDebitEnableBundle(ddKey1, Some(dd1.bundle.name))
      _ <- service.updateDataDebitBundle(ddKey1, dd2, owner.userId)
      _ <- service.dataDebitEnableBundle(ddKey1, Some(dd2.bundle.name))
      _ <- service.dataDebitDisable(ddKey1)
      saved <- service.dataDebit(ddKey1)
    } yield saved

    val maybeDebit = Await.result(saved, 10.seconds)
    maybeDebit should be('defined)
    val debit = maybeDebit.get
    debit.bundles.length should equal(2)
    debit.bundles.exists(_.enabled == true) should be(false)
  }

  "The `updateDataDebitBundle` method" should "Update a data debit by inserting an additional bundle" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val ddKey1  = Random.alphanumeric.take(10).mkString
    val ddKey2  = Random.alphanumeric.take(10).mkString
    val dd1     = newTestDataDebitRequest(ddKey1)
    val dd2     = newTestDataDebitRequestUpdate(ddKey2)
    val saved = for {
      _ <- service.createDataDebit(ddKey1, dd1, owner.userId)
      updated <- service.updateDataDebitBundle(ddKey1, dd2, owner.userId)
    } yield updated

    val debit = Await.result(saved, 10.seconds)
    debit.client.email should equal(owner.email)
    debit.dataDebitKey should equal(ddKey1)
    debit.bundles.length should equal(2)
    debit.bundles.head.enabled should be(false)
    debit.currentBundle should be('defined)
    debit.currentBundle.get.bundle.name should equal(dd2.bundle.name)
    debit.activeBundle should not be 'defined
  }

  it should "Throw an error when updating with an existing bundle" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val saved = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      updated <- service.updateDataDebitBundle("testdd",
                                               testDataDebitRequestUpdate.copy(bundle = testDataDebitRequest.bundle),
                                               owner.userId
                 )
    } yield updated

    saved
      .flatMap { result =>
        result match {
          // This should fail with an exception, so return a fail() on success.
          case _ => fail()
        }
      }
      .recover { failedResult =>
        failedResult match {
          case (_: RichDataDuplicateBundleException) => Future.successful(true)
        }
      }

  }

  // "The `all` method" should {
  //   "List all setup data debits" in {
  //     val service = application.injector.instanceOf[DataDebitContractService]

  //     val saved = for {
  //       _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
  //       _ <- service.createDataDebit("testdd2", testDataDebitRequestUpdate, owner.userId)
  //       saved <- service.all()
  //     } yield saved

  //     saved map { debits =>
  //       debits.length must be equalTo 2
  //     } await (3, 10.seconds)
  //   }
  // }

}

trait DataDebitContractServiceContext extends RichBundleServiceContext {
  def newTestDataDebitRequest(rnd: String): DataDebitRequest =
    DataDebitRequest(testBundleWithRandom(rnd),
                     None,
                     LocalDateTime.now(),
                     LocalDateTime.now().plusDays(3),
                     rolling = false
    )
  val testDataDebitRequest =
    DataDebitRequest(testBundle, None, LocalDateTime.now(), LocalDateTime.now().plusDays(3), rolling = false)

  def newTestDataDebitRequestUpdate(rnd: String): DataDebitRequest =
    DataDebitRequest(testBundleWithRandom(rnd),
                     None,
                     LocalDateTime.now(),
                     LocalDateTime.now().plusDays(3),
                     rolling = false
    )

  val testDataDebitRequestUpdate =
    DataDebitRequest(testBundle2, None, LocalDateTime.now(), LocalDateTime.now().plusDays(3), rolling = false)
}
