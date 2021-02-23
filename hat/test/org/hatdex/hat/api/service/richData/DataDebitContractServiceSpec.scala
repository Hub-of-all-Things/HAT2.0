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

import scala.concurrent.Await
import scala.concurrent.duration._
import io.dataswift.test.common.BaseSpec
import org.scalatest.{ BeforeAndAfterAll, BeforeAndAfterEach }

class DataDebitContractServiceSpec
    extends BaseSpec
    with BeforeAndAfterEach
    with BeforeAndAfterAll
    with DataDebitContractServiceContext {

  import scala.concurrent.ExecutionContext.Implicits.global
  val logger = Logger(this.getClass)

  override def beforeAll: Unit =
    Await.result(databaseReady, 60.seconds)

  override def afterAll() =
    container.stop()

  override def beforeEach: Unit = {
    import org.hatdex.hat.dal.Tables._
    import org.hatdex.libs.dal.HATPostgresProfile.api._

    val action = DBIO.seq(
      SheFunction.delete,
      DataDebitBundle.delete,
      DataDebitContract.delete,
      DataCombinators.delete,
      DataBundles.delete,
      DataJsonGroupRecords.delete,
      DataJsonGroups.delete,
      DataJson.delete
    )

    Await.result(db.run(action), 60.seconds)
  }

  "The `createDataDebit` method" should "Save a data debit" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val saved   = service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
    saved map { debit =>
      debit.client.email must equal(owner.email)
      debit.dataDebitKey must equal("testdd")
      debit.bundles.length must equal(1)
      debit.bundles.head.rolling must equal(false)
      debit.bundles.head.enabled must equal(false)
    }
    Await.result(saved, 10.seconds)
  }

  it should "Throw an error when a duplicate data debit is getting saved" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    try for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      saved <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
    } yield saved
    catch {
      case (e: Exception) =>
        true
      case _: Throwable =>
        fail()
    }
  }

  "The `dataDebit` method" should "Return a data debit by ID" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val saved = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      saved <- service.dataDebit("testdd")
    } yield saved

    saved map { maybeDebit =>
      maybeDebit must not be empty
      val debit = maybeDebit.get
      debit.client.email must equal(owner.email)
      debit.dataDebitKey must equal("testdd")
      debit.bundles.length must equal(1)
      debit.bundles.head.enabled must equal(false)
    }
    Await.result(saved, 10.seconds)
  }

  it should "Return None when data debit doesn't exist" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val saved = for {
      saved <- service.dataDebit("testdd")
    } yield saved

    saved map { maybeDebit =>
      maybeDebit must equal(empty)
    }
    Await.result(saved, 10.seconds)
  }

  "The `dataDebitEnable` method" should "Enable an existing data debit" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val saved = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      _ <- service.dataDebitEnableBundle("testdd", None)
      saved <- service.dataDebit("testdd")
    } yield saved

    saved map { maybeDebit =>
      maybeDebit must not be empty
      val debit = maybeDebit.get
      debit.client.email must equal(owner.email)
      debit.dataDebitKey must equal("testdd")
      debit.bundles.length must equal(1)
      debit.bundles.head.enabled must equal(true)
      debit.activeBundle must equal(empty)
    }
    Await.result(saved, 10.seconds)
  }

  it should "Enable a data debit after a few iterations of bundle adjustments" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val saved = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      _ <- service.updateDataDebitBundle("testdd", testDataDebitRequestUpdate, owner.userId)
      _ <- service.dataDebitEnableBundle("testdd", Some(testDataDebitRequestUpdate.bundle.name))
      saved <- service.dataDebit("testdd")
    } yield saved

    saved map { maybeDebit =>
      maybeDebit must not be empty
      val debit = maybeDebit.get
      debit.client.email must equal(owner.email)
      debit.dataDebitKey must equal("testdd")
      debit.bundles.length must equal(2)
      debit.activeBundle must not be empty
      debit.activeBundle.get.bundle.name must equal(testDataDebitRequestUpdate.bundle.name)
      debit.bundles.exists(_.enabled == false) must equal(true)
    }
    Await.result(saved, 10.seconds)
  }

  "The `dataDebitDisable` method" should "Disable all bundles linked to a data debit" in {
    val service = application.injector.instanceOf[DataDebitContractService]

    val saved = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      _ <- service.dataDebitEnableBundle("testdd", Some(testDataDebitRequest.bundle.name))
      _ <- service.updateDataDebitBundle("testdd", testDataDebitRequestUpdate, owner.userId)
      _ <- service.dataDebitEnableBundle("testdd", Some(testDataDebitRequestUpdate.bundle.name))
      _ <- service.dataDebitDisable("testdd")
      saved <- service.dataDebit("testdd")
    } yield saved

    saved map { maybeDebit =>
      maybeDebit must not be empty
      val debit = maybeDebit.get
      debit.bundles.length must equal(2)
      debit.bundles.exists(_.enabled == true) must equal(false)
    }
    Await.result(saved, 10.seconds)
  }

  "The `updateDataDebitBundle` method" should "Update a data debit by inserting an additional bundle" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    val saved = for {
      saved <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      updated <- service.updateDataDebitBundle("testdd", testDataDebitRequestUpdate, owner.userId)
    } yield updated

    saved map { debit =>
      debit.client.email must equal(owner.email)
      debit.dataDebitKey must equal("testdd")
      debit.bundles.length must equal(2)
      debit.bundles.head.enabled must equal(false)
      debit.currentBundle must not be empty
      debit.currentBundle.get.bundle.name must equal(testBundle2.name)
      debit.activeBundle must equal(empty)
    }
    Await.result(saved, 10.seconds)
  }

  it should "Throw an error when updating with an existing bundle" in {
    val service = application.injector.instanceOf[DataDebitContractService]
    try for {
      saved <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      updated <- service.updateDataDebitBundle("testdd",
                                               testDataDebitRequestUpdate.copy(bundle = testDataDebitRequest.bundle),
                                               owner.userId
                 )
    } yield updated
    catch {
      case (rdde: RichDataDuplicateBundleException) =>
        true
      case _: Throwable =>
        fail()
    }
  }

  "The `all` method" should "List all setup data debits" in {
    val service = application.injector.instanceOf[DataDebitContractService]

    val saved = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      _ <- service.createDataDebit("testdd2", testDataDebitRequestUpdate, owner.userId)
      saved <- service.all()
    } yield saved

    saved map { debits =>
      debits.length must equal(2)
    }
    Await.result(saved, 10.seconds)
  }
}

trait DataDebitContractServiceContext extends RichBundleServiceContext {
  val testDataDebitRequest =
    DataDebitRequest(testBundle, None, LocalDateTime.now(), LocalDateTime.now().plusDays(3), rolling = false)
  val testDataDebitRequestUpdate =
    DataDebitRequest(testBundle2, None, LocalDateTime.now(), LocalDateTime.now().plusDays(3), rolling = false)
}
