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
 * 4 / 2018
 */

package org.hatdex.hat.api.service.richData

import org.hatdex.hat.api.models._
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

class DataDebitServiceSpec
    extends AnyFlatSpec
    with Matchers
    with DataDebitServiceSpecContext
    with ContainerUtils
    with ForAllTestContainer {

  // Ephemeral PG Container for this test suite
  override val container = PostgreSQLContainer()
  container.start()

  val hatAddress            = "hat.hubofallthings.net"
  val logger                = Logger(this.getClass)
  private val configuration = Configuration.from(FakeHatConfiguration.config)
  private val keyUtils      = new KeyUtils()
  private val hatConfig     = configuration.get[Configuration](s"hat.$hatAddress")
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

  val conf = containerToConfig(container)

  Await.result(databaseReady(db, conf), 60.seconds)

  "The `createDataDebit` method" should "Save a data debit" in {
    val service = application.injector.instanceOf[DataDebitService]
    val ddKey   = "testdd"
    val saved   = service.createDataDebit(ddKey, newTestDataDebitRequest(ddKey), owner.userId)

    val debit = Await.result(saved, 10.seconds)
    debit.dataDebitKey should equal(ddKey)
    debit.permissions.length should equal(1)
    debit.permissions.head.active should equal(false)
  }

  it should "Throw an error when a duplicate data debit is getting saved" in {
    val service = application.injector.instanceOf[DataDebitService]
    val ddKey   = "testdd"
    val saved = for {
      _ <- service.createDataDebit(ddKey, newTestDataDebitRequest(ddKey), owner.userId)
      saved <- service.createDataDebit(ddKey, newTestDataDebitDetailsUpdate(ddKey), owner.userId)
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
          case (_: RichDataDuplicateDebitException) => Future.successful(true)
        }
      }
  }

  it should "Throw an error when a different data debit with same bundle ID is getting saved" in {
    val service = application.injector.instanceOf[DataDebitService]
    val ddKey1  = Random.alphanumeric.take(10).mkString
    val ddKey2  = Random.alphanumeric.take(10).mkString
    val saved = for {
      _ <- service.createDataDebit(ddKey1, newTestDataDebitRequest(ddKey1), owner.userId)
      saved <- service.createDataDebit(ddKey2, newTestDataDebitDetailsUpdate(ddKey2), owner.userId)
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
          case (_: RichDataDuplicateDebitException) => Future.successful(true)
        }
      }
  }

  "The `dataDebit` method" should "Return a data debit by ID" in {
    val service = application.injector.instanceOf[DataDebitService]
    val ddKey1  = Random.alphanumeric.take(10).mkString
    val ddKey2  = Random.alphanumeric.take(10).mkString
    val dd1     = newTestDataDebitRequest(ddKey1)
    val dd2     = newTestDataDebitRequestUpdate(ddKey2)

    val saved = for {
      _ <- service.createDataDebit(ddKey1, dd1, owner.userId)
      _ <- service.createDataDebit(ddKey2, dd2, owner.userId)
      saved <- service.dataDebit(ddKey1)
    } yield saved

    val maybeDebit = Await.result(saved, 10.seconds)
    maybeDebit should be('defined)
    val debit = maybeDebit.get
    debit.dataDebitKey should equal(ddKey1)
    debit.permissions.length should equal(1)
    debit.permissions.head.active should equal(false)
    debit.permissions.head.bundle.name should equal(dd1.bundle.name)
  }

  it should "Return None when data debit doesn't exist" in {
    val service = application.injector.instanceOf[DataDebitService]
    val ddKey   = Random.alphanumeric.take(20).mkString
    val saved = for {
      saved <- service.dataDebit(ddKey)
    } yield saved

    val maybeDebit = Await.result(saved, 10.seconds)
    maybeDebit should not be 'defined
  }

  "The `dataDebitEnable` method" should "Enable an existing data debit" in {
    val service = application.injector.instanceOf[DataDebitService]
    val ddKey   = Random.alphanumeric.take(20).mkString
    val saved = for {
      _ <- service.createDataDebit(ddKey, newTestDataDebitRequest(ddKey), owner.userId)
      _ <- service.dataDebitEnableNewestPermissions(ddKey)
      saved <- service.dataDebit(ddKey)
    } yield saved

    val maybeDebit = Await.result(saved, 10.seconds)
    maybeDebit should be('defined)
    val debit = maybeDebit.get
    debit.dataDebitKey should equal(ddKey)
    debit.permissions.length should equal(1)
    debit.permissions.head.active should equal(true)
    debit.activePermissions should be('defined)
  }

  it should "Enable a data debit after a few iterations of bundle adjustments" in {
    val service = application.injector.instanceOf[DataDebitService]
    val ddKey   = Random.alphanumeric.take(10).mkString
    val dd1     = newTestDataDebitRequest(ddKey)
    val dd2     = newTestDataDebitRequestUpdate(ddKey)

    val saved = for {
      _ <- service.createDataDebit(ddKey, dd1, owner.userId)
      _ <- service.updateDataDebitPermissions(ddKey, dd2, owner.userId)
      _ <- service.dataDebitEnableNewestPermissions(ddKey)
      saved <- service.dataDebit(ddKey)
    } yield saved

    val maybeDebit = Await.result(saved, 10.seconds)
    maybeDebit should be('defined)
    val debit = maybeDebit.get
    debit.dataDebitKey should equal(ddKey)
    debit.permissions.length should equal(2)
    debit.activePermissions should be('defined)
    debit.activePermissions.get.bundle.name should equal(dd2.bundle.name)
    // ???: Did I rewrite the test incorrectly
    debit.permissions.exists(_.active == false) should equal(true)
  }

  "The `dataDebitDisable` method" should "Disable all bundles linked to a data debit" in {
    val service = application.injector.instanceOf[DataDebitService]
    val ddKey   = Random.alphanumeric.take(10).mkString
    val dd1     = newTestDataDebitRequest(ddKey)
    val dd2     = newTestDataDebitRequestUpdate(ddKey)

    val saved = for {
      _ <- service.createDataDebit(ddKey, dd1, owner.userId)
      _ <- service.dataDebitEnableNewestPermissions(ddKey)
      _ <- service.updateDataDebitPermissions(ddKey, dd2, owner.userId)
      _ <- service.dataDebitEnableNewestPermissions(ddKey)
      _ <- service.dataDebitDisable(ddKey, cancelAtPeriodEnd = false)
      saved <- service.dataDebit(ddKey)
    } yield saved

    val maybeDebit = Await.result(saved, 10.seconds)
    maybeDebit should be('defined)
    val debit = maybeDebit.get
    debit.permissions.length should equal(2)
    debit.permissions.exists(_.active == true) should equal(false)
  }

  "The `updateDataDebitPermissions` method" should "Update a data debit by inserting an additional bundle" in {
    val service = application.injector.instanceOf[DataDebitService]
    val ddKey   = Random.alphanumeric.take(10).mkString
    val dd1     = newTestDataDebitRequest(ddKey)
    val dd2     = newTestDataDebitRequestUpdate(ddKey)

    val saved = for {
      _ <- service.createDataDebit(ddKey, dd1, owner.userId)
      updated <- service.updateDataDebitPermissions(ddKey, dd2, owner.userId)
    } yield updated

    val debit = Await.result(saved, 10.seconds)
    debit.dataDebitKey should equal(ddKey)
    debit.permissions.length should equal(2)
    debit.permissions.head.active should equal(false)
    debit.currentPermissions should be('defined)
    debit.currentPermissions.get.bundle.name should equal(dd2.bundle.name)
    debit.activePermissions should not be 'defined
  }

  it should "Update a data debit by inserting an additional conditions bundle" in {
    val service = application.injector.instanceOf[DataDebitService]
    val ddKey   = Random.alphanumeric.take(10).mkString
    val dd1     = newTestDataDebitRequest(ddKey)
    val dd2     = newTestDataDebitRequestUpdateConditions(ddKey)

    val saved = for {
      _ <- service.createDataDebit(ddKey, dd1, owner.userId)
      updated <- service.updateDataDebitPermissions(ddKey, dd2, owner.userId)
    } yield updated

    val debit = Await.result(saved, 10.seconds)
    debit.dataDebitKey should equal(ddKey)
    debit.permissions.length should equal(2)
    debit.permissions.head.active should equal(false)
    debit.currentPermissions should be('defined)
    debit.currentPermissions.get.bundle.name should equal(dd2.bundle.name)
    debit.activePermissions should not be 'defined
  }

  it should "Update data debit without changing bundle linked to this debit" in {
    val service = application.injector.instanceOf[DataDebitService]
    val ddKey   = Random.alphanumeric.take(10).mkString
    val dd1     = newTestDataDebitRequest(ddKey)
    val dd2     = newTestDataDebitRequestUpdate(ddKey)

    val saved = for {
      _ <- service.createDataDebit(ddKey, dd1, owner.userId)
      updated <- service.updateDataDebitPermissions(ddKey, dd2, owner.userId)
    } yield updated

    val debit = Await.result(saved, 10.seconds)
    debit.dataDebitKey should equal(ddKey)
    debit.permissions.length should equal(2)
    debit.permissions.head.active should equal(false)
    debit.currentPermissions should be('defined)
    debit.currentPermissions.get.bundle.name should equal(dd2.bundle.name)
    debit.activePermissions should not be 'defined
  }

  it should "Throw an error when updating data debit that does not already exist" in {
    val service = application.injector.instanceOf[DataDebitService]
    val saved = for {
      updated <- service.updateDataDebitPermissions("testdd2", testDataDebitDetailsUpdate, owner.userId)
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
          case (_: RichDataDebitException) => Future.successful(true)
        }
      }

  }

  it should "Throw an error when updating data debit with bundle linked to another debit" in {
    val service = application.injector.instanceOf[DataDebitService]
    val saved = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      _ <- service.createDataDebit("testdd2", testDataDebitRequestUpdate, owner.userId)
      updated <-
        service.updateDataDebitPermissions("testdd2",
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

  it should "Throw an error when updating data debit with conditions bundle linked to another debit" in {
    val service = application.injector.instanceOf[DataDebitService]
    val saved = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      _ <- service.createDataDebit("testdd2", testDataDebitRequestUpdate, owner.userId)
      updated <- service.updateDataDebitPermissions(
                   "testdd2",
                   testDataDebitRequestUpdate.copy(conditions = testDataDebitRequest.conditions),
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

  "The `all` method" should "List all setup data debits" in {
    val service = application.injector.instanceOf[DataDebitService]

    val ddKey1 = Random.alphanumeric.take(10).mkString
    val ddKey2 = Random.alphanumeric.take(10).mkString

    val saved = for {
      _ <- service.createDataDebit(ddKey1, newTestDataDebitRequest(ddKey1), owner.userId)
      _ <- service.createDataDebit(ddKey2, newTestDataDebitRequestUpdate(ddKey2), owner.userId)
      saved <- service.all()
    } yield saved

    val debits = Await.result(saved, 10.seconds)
    debits.length should equal(13)
  }
}

trait DataDebitServiceSpecContext extends RichBundleServiceContext {
  def newTestDataDebitRequest(dataDebitKey: String): DataDebitSetupRequest =
    DataDebitSetupRequest(
      dataDebitKey,
      "purpose of the data use",
      org.joda.time.DateTime.now(),
      org.joda.time.Duration.standardDays(5),
      false,
      "clientName",
      "http://client.com",
      "http://client.com/logo.png",
      None,
      None,
      Some("Detailed description of the data debit"),
      "http://client.com/terms.html",
      Some(newConditionsBundle(dataDebitKey)),
      testBundleWithRandom(dataDebitKey)
    )

  val testDataDebitRequest: DataDebitSetupRequest = newTestDataDebitRequest("testdd")

  def newTestDataDebitDetailsUpdate(dataDebitKey: String): DataDebitSetupRequest =
    DataDebitSetupRequest(
      dataDebitKey,
      "updated purpose of the data use",
      org.joda.time.DateTime.now(),
      org.joda.time.Duration.standardDays(15),
      false,
      "clientName",
      "http://client.com",
      "http://client.com/logo.png",
      None,
      None,
      Some("Detailed description of the data debit"),
      "http://client.com/terms.html",
      Some(newConditionsBundle(dataDebitKey)),
      testBundleWithRandom(dataDebitKey)
    )

  val testDataDebitDetailsUpdate = newTestDataDebitDetailsUpdate("testdd")

  def newTestDataDebitRequestUpdate(dataDebitKey: String): DataDebitSetupRequest =
    DataDebitSetupRequest(
      dataDebitKey,
      "updated purpose of the data use",
      org.joda.time.DateTime.now(),
      org.joda.time.Duration.standardDays(10),
      false,
      "clientName",
      "http://client.com",
      "http://client.com/logo.png",
      None,
      None,
      Some("Detailed description of the data debit"),
      "http://client.com/terms.html",
      None,
      testBundleWithRandom(dataDebitKey)
    )
  val testDataDebitRequestUpdate = newTestDataDebitRequestUpdate("testdd")

  def newTestDataDebitRequestUpdateConditions(dataDebitKey: String): DataDebitSetupRequest =
    DataDebitSetupRequest(
      dataDebitKey,
      "updated purpose of the data use",
      org.joda.time.DateTime.now(),
      org.joda.time.Duration.standardDays(10),
      false,
      "clientName",
      "http://client.com",
      "http://client.com/logo.png",
      None,
      None,
      Some("Detailed description of the data debit"),
      "http://client.com/terms.html",
      Some(newConditionsBundle2(dataDebitKey)),
      testBundleWithRandom(dataDebitKey)
    )

  val testDataDebitRequestUpdateConditions: DataDebitSetupRequest = DataDebitSetupRequest(
    "testdd",
    "updated purpose of the data use",
    org.joda.time.DateTime.now(),
    org.joda.time.Duration.standardDays(10),
    false,
    "clientName",
    "http://client.com",
    "http://client.com/logo.png",
    None,
    None,
    Some("Detailed description of the data debit"),
    "http://client.com/terms.html",
    Some(conditionsBundle2),
    testBundle2
  )
}
