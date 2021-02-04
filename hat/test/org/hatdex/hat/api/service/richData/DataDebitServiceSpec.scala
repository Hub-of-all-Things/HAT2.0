// /*
//  * Copyright (C) 2017 HAT Data Exchange Ltd
//  * SPDX-License-Identifier: AGPL-3.0
//  *
//  * This file is part of the Hub of All Things project (HAT).
//  *
//  * HAT is free software: you can redistribute it and/or modify
//  * it under the terms of the GNU Affero General Public License
//  * as published by the Free Software Foundation, version 3 of
//  * the License.
//  *
//  * HAT is distributed in the hope that it will be useful, but
//  * WITHOUT ANY WARRANTY; without even the implied warranty of
//  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
//  * the GNU Affero General Public License for more details.
//  *
//  * You should have received a copy of the GNU Affero General
//  * Public License along with this program. If not, see
//  * <http://www.gnu.org/licenses/>.
//  *
//  * Written by Andrius Aucinas <andrius.aucinas@hatdex.org>
//  * 4 / 2018
//  */

// package org.hatdex.hat.api.service.richData

// import org.hatdex.hat.api.models._
// import org.specs2.concurrent.ExecutionEnv
// import org.specs2.mock.Mockito
// import org.specs2.specification.{ BeforeAll, BeforeEach }
// import play.api.Logger
// import play.api.test.PlaySpecification

// import scala.concurrent.Await
// import scala.concurrent.duration._

// class DataDebitServiceSpec(implicit ee: ExecutionEnv) extends PlaySpecification with Mockito with DataDebitServiceSpecContext with BeforeEach with BeforeAll {

//   val logger = Logger(this.getClass)

//   sequential

//   def beforeAll: Unit = {
//     Await.result(databaseReady, 60.seconds)
//   }

//   override def before: Unit = {
//     import org.hatdex.hat.dal.Tables._
//     import org.hatdex.libs.dal.HATPostgresProfile.api._

//     val endpointRecrodsQuery = DataJson.filter(_.source.like("test%")).map(_.recordId)

//     val action = DBIO.seq(
//       DataDebitPermissions.filter(_.bundleId.like("test%")).delete,
//       DataDebit.filter(_.dataDebitKey.like("test%")).delete,
//       DataCombinators.filter(_.combinatorId.like("test%")).delete,
//       DataBundles.filter(_.bundleId.like("test%")).delete,
//       DataJsonGroupRecords.filter(_.recordId in endpointRecrodsQuery).delete,
//       DataJsonGroups.filterNot(g => g.groupId in DataJsonGroupRecords.map(_.groupId)).delete,
//       DataJson.filter(r => r.recordId in endpointRecrodsQuery).delete)

//     Await.result(hatDatabase.run(action), 60.seconds)
//   }

//   "The `createDataDebit` method" should {
//     "Save a data debit" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//       saved map { debit =>
//         debit.dataDebitKey must be equalTo "testdd"
//         debit.permissions.length must be equalTo 1
//         debit.permissions.head.active must beFalse
//       } await (3, 10.seconds)
//     }

//     "Throw an error when a duplicate data debit is getting saved" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         saved <- service.createDataDebit("testdd", testDataDebitRequestUpdate, owner.userId)
//       } yield saved

//       saved must throwA[RichDataDuplicateDebitException].await(3, 10.seconds)
//     }

//     "Throw an error when a different data debit with same bundle ID is getting saved" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         saved <- service.createDataDebit("testdd2", testDataDebitDetailsUpdate.copy(dataDebitKey = "testdd2"), owner.userId)
//       } yield saved

//       saved must throwA[RichDataDuplicateBundleException].await(3, 10.seconds)
//     }
//   }

//   "The `dataDebit` method" should {
//     "Return a data debit by ID" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         _ <- service.createDataDebit("testdd2", testDataDebitRequestUpdate, owner.userId)
//         saved <- service.dataDebit("testdd")
//       } yield saved

//       saved map { maybeDebit =>
//         maybeDebit must beSome
//         val debit = maybeDebit.get
//         debit.dataDebitKey must be equalTo "testdd"
//         debit.permissions.length must be equalTo 1
//         debit.permissions.head.active must beFalse
//         debit.permissions.head.bundle.name must be equalTo testDataDebitRequest.bundle.name
//       } await (3, 10.seconds)
//     }

//     "Return None when data debit doesn't exist" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         saved <- service.dataDebit("testdd")
//       } yield saved

//       saved map { maybeDebit =>
//         maybeDebit must beNone
//       } await (3, 10.seconds)
//     }
//   }

//   "The `dataDebitEnable` method" should {
//     "Enable an existing data debit" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         _ <- service.dataDebitEnableNewestPermissions("testdd")
//         saved <- service.dataDebit("testdd")
//       } yield saved

//       saved map { maybeDebit =>
//         maybeDebit must beSome
//         val debit = maybeDebit.get
//         debit.dataDebitKey must be equalTo "testdd"
//         debit.permissions.length must be equalTo 1
//         debit.permissions.head.active must beTrue
//         debit.activePermissions must beSome
//       } await (3, 10.seconds)
//     }

//     "Enable a data debit after a few iterations of bundle adjustments" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         _ <- service.updateDataDebitPermissions("testdd", testDataDebitRequestUpdate, owner.userId)
//         _ <- service.dataDebitEnableNewestPermissions("testdd")
//         saved <- service.dataDebit("testdd")
//       } yield saved

//       saved map { maybeDebit =>
//         maybeDebit must beSome
//         val debit = maybeDebit.get
//         debit.dataDebitKey must be equalTo "testdd"
//         debit.permissions.length must be equalTo 2
//         debit.activePermissions must beSome
//         debit.activePermissions.get.bundle.name must be equalTo testDataDebitRequestUpdate.bundle.name
//         debit.permissions.exists(_.active == false) must beTrue
//       } await (3, 10.seconds)
//     }
//   }

//   "The `dataDebitDisable` method" should {
//     "Disable all bundles linked to a data debit" in {
//       val service = application.injector.instanceOf[DataDebitService]

//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         _ <- service.dataDebitEnableNewestPermissions("testdd")
//         _ <- service.updateDataDebitPermissions("testdd", testDataDebitRequestUpdate, owner.userId)
//         _ <- service.dataDebitEnableNewestPermissions("testdd")
//         _ <- service.dataDebitDisable("testdd", cancelAtPeriodEnd = false)
//         saved <- service.dataDebit("testdd")
//       } yield saved

//       saved map { maybeDebit =>
//         maybeDebit must beSome
//         val debit = maybeDebit.get
//         debit.permissions.length must be equalTo 2
//         debit.permissions.exists(_.active == true) must beFalse
//       } await (3, 10.seconds)
//     }
//   }

//   "The `updateDataDebitPermissions` method" should {
//     "Update a data debit by inserting an additional bundle" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         updated <- service.updateDataDebitPermissions("testdd", testDataDebitRequestUpdate, owner.userId)
//       } yield updated

//       saved map { debit =>
//         debit.dataDebitKey must be equalTo "testdd"
//         debit.permissions.length must be equalTo 2
//         debit.permissions.head.active must beFalse
//         debit.currentPermissions must beSome
//         debit.currentPermissions.get.bundle.name must be equalTo testBundle2.name
//         debit.activePermissions must beNone
//       } await (3, 10.seconds)
//     }

//     "Update a data debit by inserting an additional conditions bundle" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         updated <- service.updateDataDebitPermissions("testdd", testDataDebitRequestUpdateConditions, owner.userId)
//       } yield updated

//       saved map { debit =>
//         debit.dataDebitKey must be equalTo "testdd"
//         debit.permissions.length must be equalTo 2
//         debit.permissions.head.active must beFalse
//         debit.currentPermissions must beSome
//         debit.currentPermissions.get.bundle.name must be equalTo testBundle2.name
//         debit.activePermissions must beNone
//       } await (3, 10.seconds)
//     }

//     "Update data debit without changing bundle linked to this debit" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         updated <- service.updateDataDebitPermissions("testdd", testDataDebitDetailsUpdate, owner.userId)
//       } yield updated

//       saved map { debit =>
//         debit.dataDebitKey must be equalTo "testdd"
//         debit.permissions.length must be equalTo 2
//         debit.permissions.head.active must beFalse
//         debit.currentPermissions must beSome
//         debit.currentPermissions.get.bundle.name must be equalTo testBundle.name
//         debit.activePermissions must beNone
//       } await (3, 10.seconds)
//     }

//     "Throw an error when updating data debit that does not already exist" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         updated <- service.updateDataDebitPermissions("testdd2", testDataDebitDetailsUpdate, owner.userId)
//       } yield updated

//       saved must throwA[RichDataDebitException].await(3, 10.seconds)
//     }

//     "Throw an error when updating data debit with bundle linked to another debit" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         _ <- service.createDataDebit("testdd2", testDataDebitRequestUpdate, owner.userId)
//         updated <- service.updateDataDebitPermissions("testdd2", testDataDebitRequestUpdate.copy(bundle = testDataDebitRequest.bundle), owner.userId)
//       } yield updated

//       saved must throwA[RichDataDuplicateBundleException].await(3, 10.seconds)
//     }

//     "Throw an error when updating data debit with conditions bundle linked to another debit" in {
//       val service = application.injector.instanceOf[DataDebitService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         _ <- service.createDataDebit("testdd2", testDataDebitRequestUpdate, owner.userId)
//         updated <- service.updateDataDebitPermissions("testdd2", testDataDebitRequestUpdate.copy(conditions = testDataDebitRequest.conditions), owner.userId)
//       } yield updated

//       saved must throwA[RichDataDuplicateBundleException].await(3, 10.seconds)
//     }
//   }

//   "The `all` method" should {
//     "List all setup data debits" in {
//       val service = application.injector.instanceOf[DataDebitService]

//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         _ <- service.createDataDebit("testdd2", testDataDebitRequestUpdate, owner.userId)
//         saved <- service.all()
//       } yield saved

//       saved map { debits =>
//         debits.length must be equalTo 2
//       } await (3, 10.seconds)
//     }
//   }

// }

// trait DataDebitServiceSpecContext extends RichBundleServiceContext {
//   val testDataDebitRequest: DataDebitSetupRequest = DataDebitSetupRequest(
//     "testdd", "purpose of the data use", org.joda.time.DateTime.now(), org.joda.time.Duration.standardDays(5), false,
//     "clientName", "http://client.com", "http://client.com/logo.png", None, None, Some("Detailed description of the data debit"),
//     "http://client.com/terms.html", Some(conditionsBundle), testBundle)

//   val testDataDebitDetailsUpdate: DataDebitSetupRequest = DataDebitSetupRequest(
//     "testdd", "updated purpose of the data use", org.joda.time.DateTime.now(), org.joda.time.Duration.standardDays(15), false,
//     "clientName", "http://client.com", "http://client.com/logo.png", None, None, Some("Detailed description of the data debit"),
//     "http://client.com/terms.html", Some(conditionsBundle), testBundle)

//   val testDataDebitRequestUpdate: DataDebitSetupRequest = DataDebitSetupRequest(
//     "testdd", "updated purpose of the data use", org.joda.time.DateTime.now(), org.joda.time.Duration.standardDays(10), false,
//     "clientName", "http://client.com", "http://client.com/logo.png", None, None, Some("Detailed description of the data debit"),
//     "http://client.com/terms.html", None, testBundle2)

//   val testDataDebitRequestUpdateConditions: DataDebitSetupRequest = DataDebitSetupRequest(
//     "testdd", "updated purpose of the data use", org.joda.time.DateTime.now(), org.joda.time.Duration.standardDays(10), false,
//     "clientName", "http://client.com", "http://client.com/logo.png", None, None, Some("Detailed description of the data debit"),
//     "http://client.com/terms.html", Some(conditionsBundle2), testBundle2)
// }
