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
 * 7 / 2018
 */

package org.hatdex.hat.api.service.richData

import org.hatdex.hat.api.models._
import org.joda.time.DateTime
import org.specs2.concurrent.ExecutionEnv
import org.specs2.mock.Mockito
import org.specs2.specification.{ BeforeAll, BeforeEach }
import play.api.Logger
import play.api.test.PlaySpecification

import scala.concurrent.Await
import scala.concurrent.duration._
import io.dataswift.test.common.BaseSpec
import org.scalatest.{ BeforeAndAfterAll, BeforeAndAfterEach }

class DataSentintelSpec extends BaseSpec with BeforeAndAfterEach with BeforeAndAfterAll with RichDataServiceContext {

  val logger = Logger(this.getClass)
  import scala.concurrent.ExecutionContext.Implicits.global

  override def beforeAll: Unit =
    Await.result(databaseReady, 60.seconds)

  override def afterAll() =
    container.stop()

  override def beforeEach: Unit = {
    import org.hatdex.hat.dal.Tables._
    import org.hatdex.libs.dal.HATPostgresProfile.api._

    val endpointRecrodsQuery = DataJson.filter(_.source.like("test%")).map(_.recordId)

    val action = DBIO.seq(
      DataDebitBundle.filter(_.bundleId.like("test%")).delete,
      DataDebitContract.filter(_.dataDebitKey.like("test%")).delete,
      DataCombinators.filter(_.combinatorId.like("test%")).delete,
      DataBundles.filter(_.bundleId.like("test%")).delete,
      DataJsonGroupRecords.filter(_.recordId in endpointRecrodsQuery).delete,
      DataJsonGroups.filterNot(g => g.groupId in DataJsonGroupRecords.map(_.groupId)).delete,
      DataJson.filter(r => r.recordId in endpointRecrodsQuery).delete
    )

    Await.result(db.run(action), 60.seconds)
  }

  "The `ensureUniquenessKey` method" should "Correctly extract item ID from data" in {
    val dataService = application.injector.instanceOf[RichDataService]
    val service     = application.injector.instanceOf[DataSentintel]

    val data = List(EndpointData("test/test", None, None, None, simpleJson, None),
                    EndpointData("test/test", None, None, None, simpleJson2, None)
    )

    val result = for {
      saved <- dataService.saveData(owner.userId, data)
      _ <- service.ensureUniquenessKey("test/test", "date")
      retrieved <- dataService.propertyData(List(EndpointQuery("test/test", None, None, None)), None, false, 0, None)
    } yield retrieved

    result map { result =>
      result.length must equal(2)
      result(0).sourceUniqueId === "1492699047"
      result(1).sourceUniqueId === "1492799048"
    }
    Await.result(result, 10.seconds)
  }

  it should "Delete duplicate records for clashing source IDs, retaining newer record" in {
    val dataService = application.injector.instanceOf[RichDataService]
    val service     = application.injector.instanceOf[DataSentintel]

    val data = List(EndpointData("test/test", None, None, None, simpleJson, None),
                    EndpointData("test/test", None, None, None, simpleJson2, None)
    )

    val result = for {
      _ <- dataService.saveData(owner.userId, data)
      _ <-
        dataService.saveData(owner.userId, List(EndpointData("test/test", None, None, None, simpleJson2Updated, None)))
      _ <- service.ensureUniquenessKey("test/test", "date")
      retrieved <- dataService.propertyData(List(EndpointQuery("test/test", None, None, None)), None, false, 0, None)
    } yield retrieved

    result map { result =>
      result.length must equal(2)
      result.find(_.sourceUniqueId.contains("1492699047")) must not be empty
      result.find(_.sourceUniqueId.contains("1492799048")) must not be empty
      (result(1).data \ "differentField").as[String] must equal("new")
    }
    Await.result(result, 10.seconds)
  }

  it should "Not touch records where extracting ID fails" in {
    val dataService = application.injector.instanceOf[RichDataService]
    val service     = application.injector.instanceOf[DataSentintel]

    val data = List(EndpointData("test/test", None, None, None, simpleJson, None),
                    EndpointData("test/test", None, None, None, simpleJson2, None)
    )

    val result = for {
      _ <- dataService.saveData(owner.userId, data)
      _ <-
        dataService.saveData(owner.userId, List(EndpointData("test/test", None, None, None, simpleJson2Updated, None)))
      _ <- service.ensureUniquenessKey("test/test", "testUniqueID")
      retrieved <- dataService.propertyData(List(EndpointQuery("test/test", None, None, None)), None, false, 0, None)
    } yield retrieved

    result map { result =>
      result.find(_.sourceUniqueId.contains("1234567")) must not be empty
      result.count(r => (r.data \ "date").asOpt[Int].contains(1492799048)) must equal(2)
    }
    Await.result(result, 10.seconds)
  }

  it should "Handle records where ID is nested deeply within the object" in {
    val dataService = application.injector.instanceOf[RichDataService]
    val service     = application.injector.instanceOf[DataSentintel]

    val data = List(EndpointData("test/test", None, None, None, simpleJson, None))

    val result = for {
      _ <- dataService.saveData(owner.userId, data)
      _ <- service.ensureUniquenessKey("test/test", "object.nestedInfo.deeplyLocatedUniqueId")
      retrieved <- dataService.propertyData(List(EndpointQuery("test/test", None, None, None)), None, false, 0, None)
    } yield retrieved

    result map { result =>
      result.find(_.sourceUniqueId.contains("7654321")) must not be empty
    }
    Await.result(result, 10.seconds)
  }

  it should "Not update records when key is specified to be within an array" in {
    val dataService = application.injector.instanceOf[RichDataService]
    val service     = application.injector.instanceOf[DataSentintel]

    val data = List(EndpointData("test/test", None, None, None, simpleJson, None))

    val result = for {
      _ <- dataService.saveData(owner.userId, data)
      _ <- service.ensureUniquenessKey("test/test", "object.objectFieldArray[]")
      retrieved <- dataService.propertyData(List(EndpointQuery("test/test", None, None, None)), None, false, 0, None)
    } yield retrieved

    result map { result =>
      result.forall(_.sourceUniqueId.isEmpty) must equal(true)
    }
    Await.result(result, 10.seconds)
  }

  "The `ensureUniquenessKey` method" should "Correctly extract ISO8601 timestamp from data" in {
    val dataService = application.injector.instanceOf[RichDataService]
    val service     = application.injector.instanceOf[DataSentintel]

    val data = List(EndpointData("test/test", None, None, None, simpleJson, None))

    val result = for {
      _ <- dataService.saveData(owner.userId, data)
      _ <- service.updateSourceTimestamp("test/test", "date_iso")
      retrieved <- dataService.propertyData(List(EndpointQuery("test/test", None, None, None)), None, false, 0, None)
    } yield retrieved

    result map { result =>
      result.head.sourceTimestamp must not be empty
      result.head.sourceTimestamp.get.isEqual(DateTime.parse("2017-04-20T14:37:27+00:00")) must equal(true)
    }
    Await.result(result, 10.seconds)
  }

  it should "Correctly extract unix timestamp in milliseconds from data" in {
    val dataService = application.injector.instanceOf[RichDataService]
    val service     = application.injector.instanceOf[DataSentintel]

    val data = List(EndpointData("test/test", None, None, None, simpleJson, None))

    val result = for {
      _ <- dataService.saveData(owner.userId, data)
      _ <- service.updateSourceTimestamp("test/test", "date_ms")
      retrieved <- dataService.propertyData(List(EndpointQuery("test/test", None, None, None)), None, false, 0, None)
    } yield retrieved

    result map { result =>
      result.head.sourceTimestamp must not be empty
      result.head.sourceTimestamp.get.isEqual(DateTime.parse("2017-04-20T14:37:27+00:00")) must equal(true)
    }
    Await.result(result, 10.seconds)
  }

  it should "Correctly extract unix timestamp in miliseconds from data" in {
    val dataService = application.injector.instanceOf[RichDataService]
    val service     = application.injector.instanceOf[DataSentintel]

    val data = List(EndpointData("test/test", None, None, None, simpleJson, None))

    val result = for {
      _ <- dataService.saveData(owner.userId, data)
      _ <- service.updateSourceTimestamp("test/test", "date", "'epoch'")
      retrieved <- dataService.propertyData(List(EndpointQuery("test/test", None, None, None)), None, false, 0, None)
    } yield retrieved

    result map { result =>
      result.head.sourceTimestamp must not be empty
      result.head.sourceTimestamp.get.isEqual(DateTime.parse("2017-04-20T14:37:27+00:00")) must equal(true)
    }
    Await.result(result, 10.seconds)
  }
}
