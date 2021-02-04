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
//  * 5 / 2017
//  */

// package org.hatdex.hat.api.service.richData

// import org.hatdex.hat.api.models._
// import org.joda.time.LocalDateTime
// import org.specs2.concurrent.ExecutionEnv
// import org.specs2.mock.Mockito
// import org.specs2.specification.{ BeforeAll, BeforeEach }
// import play.api.Logger
// import play.api.test.PlaySpecification

// import scala.concurrent.Await
// import scala.concurrent.duration._

// class DataDebitContractServiceSpec(implicit ee: ExecutionEnv) extends PlaySpecification with Mockito with DataDebitContractServiceContext with BeforeEach with BeforeAll {

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
//       DataDebitBundle.filter(_.bundleId.like("test%")).delete,
//       DataDebitContract.filter(_.dataDebitKey.like("test%")).delete,
//       DataCombinators.filter(_.combinatorId.like("test%")).delete,
//       DataBundles.filter(_.bundleId.like("test%")).delete,
//       DataJsonGroupRecords.filter(_.recordId in endpointRecrodsQuery).delete,
//       DataJsonGroups.filterNot(g => g.groupId in DataJsonGroupRecords.map(_.groupId)).delete,
//       DataJson.filter(r => r.recordId in endpointRecrodsQuery).delete)

//     Await.result(hatDatabase.run(action), 60.seconds)
//   }

//   "The `createDataDebit` method" should {
//     "Save a data debit" in {
//       val service = application.injector.instanceOf[DataDebitContractService]
//       val saved = service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//       saved map { debit =>
//         debit.client.email must be equalTo (owner.email)
//         debit.dataDebitKey must be equalTo ("testdd")
//         debit.bundles.length must be equalTo (1)
//         debit.bundles.head.rolling must beFalse
//         debit.bundles.head.enabled must beFalse
//       } await (3, 10.seconds)
//     }

//     "Throw an error when a duplicate data debit is getting saved" in {
//       val service = application.injector.instanceOf[DataDebitContractService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         saved <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//       } yield saved

//       saved must throwA[Exception].await(3, 10.seconds)
//     }
//   }

//   "The `dataDebit` method" should {
//     "Return a data debit by ID" in {
//       val service = application.injector.instanceOf[DataDebitContractService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         saved <- service.dataDebit("testdd")
//       } yield saved

//       saved map { maybeDebit =>
//         maybeDebit must beSome
//         val debit = maybeDebit.get
//         debit.client.email must be equalTo (owner.email)
//         debit.dataDebitKey must be equalTo ("testdd")
//         debit.bundles.length must be equalTo (1)
//         debit.bundles.head.enabled must beFalse
//       } await (3, 10.seconds)
//     }

//     "Return None when data debit doesn't exist" in {
//       val service = application.injector.instanceOf[DataDebitContractService]
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
//       val service = application.injector.instanceOf[DataDebitContractService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         _ <- service.dataDebitEnableBundle("testdd", None)
//         saved <- service.dataDebit("testdd")
//       } yield saved

//       saved map { maybeDebit =>
//         maybeDebit must beSome
//         val debit = maybeDebit.get
//         debit.client.email must be equalTo (owner.email)
//         debit.dataDebitKey must be equalTo ("testdd")
//         debit.bundles.length must be equalTo (1)
//         debit.bundles.head.enabled must beTrue
//         debit.activeBundle must beSome
//       } await (3, 10.seconds)
//     }

//     "Enable a data debit after a few iterations of bundle adjustments" in {
//       val service = application.injector.instanceOf[DataDebitContractService]
//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         _ <- service.updateDataDebitBundle("testdd", testDataDebitRequestUpdate, owner.userId)
//         _ <- service.dataDebitEnableBundle("testdd", Some(testDataDebitRequestUpdate.bundle.name))
//         saved <- service.dataDebit("testdd")
//       } yield saved

//       saved map { maybeDebit =>
//         maybeDebit must beSome
//         val debit = maybeDebit.get
//         debit.client.email must be equalTo (owner.email)
//         debit.dataDebitKey must be equalTo ("testdd")
//         debit.bundles.length must be equalTo (2)
//         debit.activeBundle must beSome
//         debit.activeBundle.get.bundle.name must be equalTo (testDataDebitRequestUpdate.bundle.name)
//         debit.bundles.exists(_.enabled == false) must beTrue
//       } await (3, 10.seconds)
//     }
//   }

//   "The `dataDebitDisable` method" should {
//     "Disable all bundles linked to a data debit" in {
//       val service = application.injector.instanceOf[DataDebitContractService]

//       val saved = for {
//         _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         _ <- service.dataDebitEnableBundle("testdd", Some(testDataDebitRequest.bundle.name))
//         _ <- service.updateDataDebitBundle("testdd", testDataDebitRequestUpdate, owner.userId)
//         _ <- service.dataDebitEnableBundle("testdd", Some(testDataDebitRequestUpdate.bundle.name))
//         _ <- service.dataDebitDisable("testdd")
//         saved <- service.dataDebit("testdd")
//       } yield saved

//       saved map { maybeDebit =>
//         maybeDebit must beSome
//         val debit = maybeDebit.get
//         debit.bundles.length must be equalTo (2)
//         debit.bundles.exists(_.enabled == true) must beFalse
//       } await (3, 10.seconds)
//     }
//   }

//   "The `updateDataDebitBundle` method" should {
//     "Update a data debit by inserting an additional bundle" in {
//       val service = application.injector.instanceOf[DataDebitContractService]
//       val saved = for {
//         saved <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         updated <- service.updateDataDebitBundle("testdd", testDataDebitRequestUpdate, owner.userId)
//       } yield updated

//       saved map { debit =>
//         debit.client.email must be equalTo (owner.email)
//         debit.dataDebitKey must be equalTo ("testdd")
//         debit.bundles.length must be equalTo (2)
//         debit.bundles.head.enabled must beFalse
//         debit.currentBundle must beSome
//         debit.currentBundle.get.bundle.name must be equalTo (testBundle2.name)
//         debit.activeBundle must beNone
//       } await (3, 10.seconds)
//     }

//     "Throw an error when updating with an existing bundle" in {
//       val service = application.injector.instanceOf[DataDebitContractService]
//       val saved = for {
//         saved <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
//         updated <- service.updateDataDebitBundle("testdd", testDataDebitRequestUpdate.copy(bundle = testDataDebitRequest.bundle), owner.userId)
//       } yield updated

//       saved must throwA[RichDataDuplicateBundleException].await(3, 10.seconds)
//     }
//   }

//   "The `all` method" should {
//     "List all setup data debits" in {
//       val service = application.injector.instanceOf[DataDebitContractService]

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

// trait DataDebitContractServiceContext extends RichBundleServiceContext {
//   val testDataDebitRequest = DataDebitRequest(testBundle, None, LocalDateTime.now(), LocalDateTime.now().plusDays(3), rolling = false)
//   val testDataDebitRequestUpdate = DataDebitRequest(testBundle2, None, LocalDateTime.now(), LocalDateTime.now().plusDays(3), rolling = false)
// }
