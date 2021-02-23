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

package org.hatdex.hat.api.controllers

import com.mohiva.play.silhouette.test._
import org.hatdex.hat.api.HATTestContext
import org.hatdex.hat.api.models._
import org.hatdex.hat.api.service.richData.{ DataDebitContractService, RichDataService }
import org.joda.time.LocalDateTime
import play.api.Logger
import play.api.libs.json.{ JsArray, JsObject, JsValue, Json }
import play.api.mvc.Result
import play.api.test.{ FakeRequest, Helpers }

import scala.concurrent.duration._
import scala.concurrent.{ Await, Future }
import io.dataswift.test.common.BaseSpec
import org.scalatest.{ BeforeAndAfterAll, BeforeAndAfterEach }
import play.api.test.Helpers
import play.api.test.Helpers._

class RichDataSpec extends BaseSpec with BeforeAndAfterEach with BeforeAndAfterAll with RichDataContext {
  import scala.concurrent.ExecutionContext.Implicits.global
  import org.hatdex.hat.api.json.RichDataJsonFormats._

  val logger = Logger(this.getClass)

  override def beforeAll: Unit =
    Await.result(databaseReady, 60.seconds)

  override def afterAll() =
    container.stop()

  override def beforeEach: Unit = {
    import org.hatdex.hat.dal.Tables._
    import org.hatdex.libs.dal.HATPostgresProfile.api._

    val endpointRecordsQuery = DataJson.filter(_.source.like("test%")).map(_.recordId)

    val action = DBIO.seq(
      DataDebitBundle.filter(_.bundleId.like("test%")).delete,
      DataDebitContract.filter(_.dataDebitKey.like("test%")).delete,
      DataCombinators.filter(_.combinatorId.like("test%")).delete,
      DataBundles.filter(_.bundleId.like("test%")).delete,
      DataJsonGroupRecords.filter(_.recordId in endpointRecordsQuery).delete,
      DataJsonGroups.filterNot(g => g.groupId in DataJsonGroupRecords.map(_.groupId)).delete,
      DataJson.filter(r => r.recordId in endpointRecordsQuery).delete
    )

    Await.result(db.run(action), 60.seconds)
  }

  "The Saving and Reading data" should "must be equivalent" in {
    val service = application.injector.instanceOf[RichDataService]

    val dataEndpoint = "samplecontract/a/b"
    val values       = Seq(EndpointData(dataEndpoint, None, None, None, nestedJson, None))
    val futSaved = service
      .saveData(owner.userId, values)

    val saved = Await.result(futSaved, 10.seconds)
    saved.length must equal(1)
    Json.toJson(saved.head.data) must equal(nestedJson)

    val query =
      Seq(EndpointQuery(dataEndpoint, None, None, None))
    val data = service.propertyData(
      query,
      None,
      true,
      0,
      Some(10)
    )

    val res = Await.result(data, 10.seconds)
    res.length must equal(1)
    Json.toJson(res.head.data) must equal(nestedJson)
  }

  "The `getEndpointData` method" should "Return an empty array for an unknown endpoint" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[RichData]

    val response     = Helpers.call(controller.getEndpointData("test", "endpoint", None, None, None, None), request)
    val responseData = contentAsJson(response).as[Seq[EndpointData]]
    responseData.length must equal(0)
  }

  it should "Order records by selected field" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[RichData]
    val service    = application.injector.instanceOf[RichDataService]

    val data = List(
      EndpointData("test/endpoint", None, None, None, simpleJson, None),
      EndpointData("test/endpoint", None, None, None, simpleJson2, None),
      EndpointData("test/endpoint", None, None, None, complexJson, None)
    )

    val response = for {
      _ <- service.saveData(owner.userId, data).map(_.head)
      r <- Helpers.call(controller.getEndpointData("test", "endpoint", Some("field"), None, None, Some(2)), request)
    } yield r
    val responseData = contentAsJson(response).as[Seq[EndpointData]]
    responseData.length must equal(2)
    responseData.head.data must equal(simpleJson)
  }

  it should "Order records by selected field in descending order" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[RichData]
    val service    = application.injector.instanceOf[RichDataService]

    val data = List(
      EndpointData("test/endpoint", None, None, None, simpleJson, None),
      EndpointData("test/endpoint", None, None, None, simpleJson2, None),
      EndpointData("test/endpoint", None, None, None, complexJson, None)
    )

    val response = for {
      _ <- service.saveData(owner.userId, data).map(_.head)
      r <- Helpers.call(
             controller.getEndpointData("test", "endpoint", Some("field"), Some("descending"), Some(1), Some(2)),
             request
           )
    } yield r
    val responseData = contentAsJson(response).as[Seq[EndpointData]]
    responseData.length must equal(2)
    responseData.head.data must equal(simpleJson)
  }

  "The `saveEndpointData` method" should "Save a single record" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(simpleJson)

    val controller = application.injector.instanceOf[RichData]

    val response = for {
      _ <- Helpers.call(controller.saveEndpointData("test", "endpoint", None), request)
      r <- Helpers.call(controller.getEndpointData("test", "endpoint", None, None, None, None), request)
    } yield r
    val responseData = contentAsJson(response).as[Seq[EndpointData]]
    responseData.length must equal(1)
    responseData.head.data must equal(simpleJson)
  }

  it should "Save multiple records" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(JsArray(Seq(simpleJson, simpleJson2)))

    val controller = application.injector.instanceOf[RichData]

    val response = for {
      _ <- Helpers.call(controller.saveEndpointData("test", "endpoint", None), request)
      r <- Helpers.call(controller.getEndpointData("test", "endpoint", None, None, None, None), request)
    } yield r
    val responseData = contentAsJson(response).as[Seq[EndpointData]]
    responseData.length must equal(2)
  }

  it should "Return an error when duplicate records are being inserted" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(JsArray(Seq(simpleJson, simpleJson, simpleJson2)))

    val controller = application.injector.instanceOf[RichData]

    val response = for {
      r <- Helpers.call(controller.saveEndpointData("test", "endpoint", None), request)
    } yield r

    status(response) must equal(BAD_REQUEST)
    val responseData = contentAsJson(response).as[ErrorMessage]
    responseData.message must equal("Bad Request")
    responseData.cause must startWith("Duplicate data -")
  }

  it should "Skip duplicate insertion errors when requested" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(JsArray(Seq(simpleJson, simpleJson, simpleJson2)))

    val controller = application.injector.instanceOf[RichData]

    val response = for {
      _ <- Helpers.call(controller.saveEndpointData("test", "endpoint", Some(true)), request)
      r <- Helpers.call(controller.getEndpointData("test", "endpoint", None, None, None, None), request)
    } yield r

    val responseData = contentAsJson(response).as[Seq[EndpointData]]
    responseData.length must equal(2)
  }

  "The `listEndpoints` method" should "Return a list of all endpoints seen so far" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(testDataDebitRequest))

    val controller = application.injector.instanceOf[RichData]

    val data = List(
      EndpointData("test/test", None, None, None, simpleJson, None),
      EndpointData("test2/test2", None, None, None, simpleJson2, None),
      EndpointData("test/test3", None, None, None, complexJson, None)
    )

    val dataService = application.injector.instanceOf[RichDataService]

    val result = for {
      _ <- dataService.saveData(owner.userId, data)
      response <- Helpers.call(controller.listEndpoints(), request)
    } yield response

    val endpoints = contentAsJson(result).as[Map[String, Seq[String]]]
    endpoints.get("test") must not be empty
    endpoints("test") must contain("test")
    endpoints("test") must contain("test3")
    endpoints.get("test2") must not be empty
    endpoints("test2") must contain("test2")
  }

  "The `deleteEndpointData` method" should "Delete all data for an endpoint" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(testDataDebitRequest))

    val controller = application.injector.instanceOf[RichData]

    val data = List(
      EndpointData("test/test", None, None, None, simpleJson, None),
      EndpointData("test2/test2", None, None, None, simpleJson2, None),
      EndpointData("test/test3", None, None, None, complexJson, None)
    )

    val dataService = application.injector.instanceOf[RichDataService]

    val result = for {
      _ <- dataService.saveData(owner.userId, data)
      _ <- Helpers.call(controller.deleteEndpointData("test", "test"), request)
      response <- Helpers.call(controller.getEndpointData("test", "test", None, None, None, None), request)
    } yield response

    val responseData = contentAsJson(result).as[Seq[EndpointData]]
    responseData.size must equal(0)
  }

  "The `saveBatchData` method" should "Save all data included in a batch" in {
    val data = List(
      EndpointData("test/test", None, None, None, simpleJson, None),
      EndpointData("test2/test2", None, None, None, simpleJson2, None),
      EndpointData("test/test", None, None, None, complexJson, None)
    )

    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(data))

    val controller = application.injector.instanceOf[RichData]

    val response = for {
      _ <- Helpers.call(controller.saveBatchData(), request)
      r <- Helpers.call(controller.getEndpointData("test", "test", None, None, None, None), request)
    } yield r

    status(response) must equal(OK)
    val responseData = contentAsJson(response).as[Seq[EndpointData]]
    responseData.length must equal(2)
  }

  it should "Reject all data if user has no permissions to write some of it" in {
    val data = List(
      EndpointData("test/test", None, None, None, simpleJson, None),
      EndpointData("test2/test2", None, None, None, simpleJson2, None),
      EndpointData("test/test3", None, None, None, complexJson, None)
    )

    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(dataCreditUser.loginInfo)
      .withJsonBody(Json.toJson(data))

    val controller = application.injector.instanceOf[RichData]

    val response = for {
      r <- Helpers.call(controller.saveBatchData(), request)
    } yield r

    status(response) must equal(FORBIDDEN)
  }

  it should "Return an error when inserting duplicate data" in {
    val data = List(
      EndpointData("test/test", None, None, None, simpleJson, None),
      EndpointData("test2/test2", None, None, None, simpleJson2, None),
      EndpointData("test/test", None, None, None, simpleJson, None)
    )

    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(data))

    val controller = application.injector.instanceOf[RichData]

    val response = for {
      r <- Helpers.call(controller.saveBatchData(), request)
    } yield r

    status(response) must equal(BAD_REQUEST)
  }

  "The `registerBundle` method" should "return accepted debit if data debit is registered" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(testDataDebitRequest))

    val controller             = application.injector.instanceOf[RichData]
    val result: Future[Result] = Helpers.call(controller.registerDataDebit("testdd"), request)

    status(result) must equal(CREATED)
    val debit = contentAsJson(result).as[RichDataDebit]
    debit.dataDebitKey must equal("testdd")
    debit.bundles.exists(_.enabled) must equal(false)
    debit.bundles.length must equal(1)
  }

  it should "return status 400 if inserting duplicate data debit" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(testDataDebitRequest))

    val controller = application.injector.instanceOf[RichData]
    val result: Future[Result] = for {
      _ <- Helpers.call(controller.registerDataDebit("testdd"), request)
      debit <- Helpers.call(controller.registerDataDebit("testdd"), request)
    } yield debit

    status(result) must equal(BAD_REQUEST)
  }

  "The `updateDataDebit` method" should "Update data debit" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(testDataDebitRequestUpdate))

    val controller = application.injector.instanceOf[RichData]
    val service    = application.injector.instanceOf[DataDebitContractService]
    val result: Future[Result] = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      debit <- Helpers.call(controller.updateDataDebit("testdd"), request)
    } yield debit

    status(result) must equal(OK)
  }

  it should "Respond with bad request if data debit does not exist" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(testDataDebitRequestUpdate))

    val controller = application.injector.instanceOf[RichData]
    val result: Future[Result] = for {
      debit <- Helpers.call(controller.updateDataDebit("testdd"), request)
    } yield debit

    status(result) must equal(BAD_REQUEST)
  }

  it should "Respond with bad request if data bundle is duplicated" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)
      .withJsonBody(Json.toJson(testDataDebitRequest))

    val controller = application.injector.instanceOf[RichData]
    val service    = application.injector.instanceOf[DataDebitContractService]
    val result: Future[Result] = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      debit <- Helpers.call(controller.updateDataDebit("testdd"), request)
    } yield debit

    status(result) must equal(BAD_REQUEST)
  }

  "The `getDataDebit` method" should "Return 404 if data debit doesn't exist" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[RichData]
    val result: Future[Result] = for {
      debit <- Helpers.call(controller.getDataDebit("testdd"), request)
    } yield debit

    status(result) must equal(NOT_FOUND)
  }

  it should "Return Data Debit information" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[RichData]
    val service    = application.injector.instanceOf[DataDebitContractService]

    val result: Future[Result] = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      debit <- Helpers.call(controller.getDataDebit("testdd"), request)
    } yield debit

    status(result) must equal(OK)
    val debit = contentAsJson(result).as[RichDataDebit]
    debit.dataDebitKey must equal("testdd")
    debit.bundles.exists(_.enabled) must equal(false)
    debit.bundles.length must equal(1)
  }

  "The `getDataDebitValues` method" should "Return 404 if the data debit doesn't exist" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[RichData]
    val result: Future[Result] = for {
      debit <- Helpers.call(controller.getDataDebitValues("testdd"), request)
    } yield debit

    status(result) must equal(NOT_FOUND)
  }

  it should "Return 403 if the data debit has not been enabled" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[RichData]
    val service    = application.injector.instanceOf[DataDebitContractService]

    val result: Future[Result] = for {
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      debit <- Helpers.call(controller.getDataDebitValues("testdd"), request)
    } yield debit

    status(result) must equal(BAD_REQUEST)
  }

  it should "Return data for matching, enabled data debit bundle" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller  = application.injector.instanceOf[RichData]
    val service     = application.injector.instanceOf[DataDebitContractService]
    val dataService = application.injector.instanceOf[RichDataService]

    val result = for {
      _ <- dataService.saveData(owner.userId, List(EndpointData("test/test", None, None, None, simpleJson, None)))
      _ <- dataService.saveData(owner.userId, List(EndpointData("test/test", None, None, None, simpleJson2, None)))
      _ <- dataService.saveData(owner.userId, List(EndpointData("test/complex", None, None, None, complexJson, None)))
      _ <- service.createDataDebit("testdd", testDataDebitRequest, owner.userId)
      _ <- service.dataDebitEnableBundle("testdd", None)
      data <- Helpers.call(controller.getDataDebitValues("testdd"), request)
    } yield data

    status(result) must equal(OK)
    val data = contentAsJson(result).as[RichDataDebitData].bundle
    //there was one(mockLogger).debug("Got Data Debit, fetching data")

    data("test").length must not equal 0
    data("test").length must not equal 0
  }

  it should "Return no data for bundle with unfulfilled conditions" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller  = application.injector.instanceOf[RichData]
    val service     = application.injector.instanceOf[DataDebitContractService]
    val dataService = application.injector.instanceOf[RichDataService]

    val result = for {
      _ <- dataService.saveData(owner.userId, List(EndpointData("test/test", None, None, None, simpleJson, None)))
      _ <- dataService.saveData(owner.userId, List(EndpointData("test/test", None, None, None, simpleJson2, None)))
      _ <- dataService.saveData(owner.userId, List(EndpointData("test/complex", None, None, None, complexJson, None)))
      _ <- service.createDataDebit("testdd", ddRequestionConditionsFailed, owner.userId)
      _ <- service.dataDebitEnableBundle("testdd", Some(ddRequestionConditionsFailed.bundle.name))
      data <- Helpers.call(controller.getDataDebitValues("testdd"), request)
    } yield data

    status(result) must equal(OK)
    val data = contentAsJson(result).as[RichDataDebitData].bundle
    data must equal(Map.empty)
  }

  it should "Return data for data debit with fulfilled conditions" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller  = application.injector.instanceOf[RichData]
    val service     = application.injector.instanceOf[DataDebitContractService]
    val dataService = application.injector.instanceOf[RichDataService]

    val result = for {
      _ <- dataService.saveData(owner.userId, List(EndpointData("test/test", None, None, None, simpleJson, None)))
      _ <- dataService.saveData(owner.userId, List(EndpointData("test/test", None, None, None, simpleJson2, None)))
      _ <- dataService.saveData(owner.userId, List(EndpointData("test/complex", None, None, None, complexJson, None)))
      _ <- service.createDataDebit("testdd", ddRequestionConditionsFulfilled, owner.userId)
      _ <- service.dataDebitEnableBundle("testdd", Some(ddRequestionConditionsFulfilled.bundle.name))
      data <- Helpers.call(controller.getDataDebitValues("testdd"), request)
    } yield data

    status(result) must equal(OK)
    val data = contentAsJson(result).as[RichDataDebitData].bundle
    //there was one(mockLogger).debug(s"Data Debit testdd conditions satisfied")
    data("test").length must not equal 0
    data("test").length must not equal 0
  }
}

trait RichDataContext extends HATTestContext {
  val nestedJson = Json.parse("""{"nested_data": {"nested": "{{sltoken}}", "value": true, "id": 33 }}""")

  val simpleJson: JsValue = Json.parse("""
      | {
      |   "field": "value",
      |   "date": 1492699047,
      |   "date_iso": "2017-04-20T14:37:27+00:00",
      |   "anotherField": "anotherFieldValue",
      |   "object": {
      |     "objectField": "objectFieldValue",
      |     "objectFieldArray": ["objectFieldArray1", "objectFieldArray2", "objectFieldArray3"],
      |     "objectFieldObjectArray": [
      |       {"subObjectName": "subObject1", "subObjectName2": "subObject1-2"},
      |       {"subObjectName": "subObject2", "subObjectName2": "subObject2-2"}
      |     ]
      |   }
      | }
    """.stripMargin)

  val simpleJson2: JsValue = Json.parse("""
      | {
      |   "field": "value2",
      |   "date": 1492799047,
      |   "date_iso": "2017-04-21T18:24:07+00:00",
      |   "anotherField": "anotherFieldDifferentValue",
      |   "object": {
      |     "objectField": "objectFieldValue",
      |     "objectFieldArray": ["objectFieldArray1", "objectFieldArray2", "objectFieldArray3"],
      |     "objectFieldObjectArray": [
      |       {"subObjectName": "subObject1", "subObjectName2": "subObject1-2"},
      |       {"subObjectName": "subObject2", "subObjectName2": "subObject2-2"}
      |     ]
      |   }
      | }
    """.stripMargin)

  val complexJson: JsValue = Json.parse("""
      | {
      |  "birthday": "01/01/1970",
      |  "age_range": {
      |    "min": 18
      |  },
      |  "education": [
      |    {
      |      "school": {
      |        "id": "123456789",
      |        "name": "school name"
      |      },
      |      "type": "High School",
      |      "year": {
      |        "id": "123456789",
      |        "name": "1972"
      |      },
      |      "id": "123456789"
      |    },
      |    {
      |      "concentration": [
      |        {
      |          "id": "123456789",
      |          "name": "Computer science"
      |        }
      |      ],
      |      "school": {
      |        "id": "12345678910",
      |        "name": "university name"
      |      },
      |      "type": "Graduate School",
      |      "year": {
      |        "id": "123456889",
      |        "name": "1973"
      |      },
      |      "id": "12345678910"
      |    }
      |  ],
      |  "email": "email@example.com",
      |  "hometown": {
      |    "id": "12345678910",
      |    "name": "london, uk"
      |  },
      |  "locale": "en_GB",
      |  "id": "12345678910"
      |}
    """.stripMargin)

  private val simpleTransformation: JsObject = Json
    .parse("""
      | {
      |   "data.newField": "anotherField",
      |   "data.arrayField": "object.objectFieldArray",
      |   "data.onemore": "object.education[1]"
      | }
    """.stripMargin)
    .as[JsObject]

  private val complexTransformation: JsObject = Json
    .parse("""
      | {
      |   "data.newField": "hometown.name",
      |   "data.arrayField": "education",
      |   "data.onemore": "education[0].type"
      | }
    """.stripMargin)
    .as[JsObject]

  val testEndpointQuery = Seq(EndpointQuery("test/test", Some(simpleTransformation), None, None),
                              EndpointQuery("test/complex", Some(complexTransformation), None, None)
  )

  val testEndpointQueryUpdated = Seq(EndpointQuery("test/test", Some(simpleTransformation), None, None),
                                     EndpointQuery("test/anothertest", None, None, None)
  )

  val testBundle = EndpointDataBundle(
    "testBundle",
    Map(
      "test" -> PropertyQuery(List(EndpointQuery("test/test", Some(simpleTransformation), None, None)),
                              Some("data.newField"),
                              None,
                              Some(3)
          ),
      "complex" -> PropertyQuery(List(EndpointQuery("test/complex", Some(complexTransformation), None, None)),
                                 Some("data.newField"),
                                 None,
                                 Some(1)
          )
    )
  )

  val failingCondition = EndpointDataBundle(
    "testfailCondition",
    Map(
      "test" -> PropertyQuery(
            List(
              EndpointQuery("test/test",
                            None,
                            Some(
                              Seq(
                                EndpointQueryFilter("field",
                                                    transformation = None,
                                                    operator = FilterOperator.Contains(Json.toJson("N/A"))
                                )
                              )
                            ),
                            None
              )
            ),
            Some("data.newField"),
            None,
            Some(3)
          )
    )
  )

  val matchingCondition = EndpointDataBundle(
    "testfailCondition",
    Map(
      "test" -> PropertyQuery(
            List(
              EndpointQuery("test/test",
                            None,
                            Some(
                              Seq(
                                EndpointQueryFilter("field",
                                                    transformation = None,
                                                    operator = FilterOperator.Contains(Json.toJson("value"))
                                )
                              )
                            ),
                            None
              )
            ),
            Some("data.newField"),
            None,
            Some(3)
          )
    )
  )

  val testBundle2 = EndpointDataBundle(
    "testBundle2",
    Map(
      "test" -> PropertyQuery(List(EndpointQuery("test/test", Some(simpleTransformation), None, None)),
                              Some("data.newField"),
                              None,
                              Some(3)
          ),
      "complex" -> PropertyQuery(List(EndpointQuery("test/anothertest", None, None, None)),
                                 Some("data.newField"),
                                 None,
                                 Some(1)
          )
    )
  )

  val testDataDebitRequest =
    DataDebitRequest(testBundle, None, LocalDateTime.now(), LocalDateTime.now().plusDays(3), rolling = false)

  val testDataDebitRequestUpdate =
    DataDebitRequest(testBundle2, None, LocalDateTime.now(), LocalDateTime.now().plusDays(3), rolling = false)

  val ddRequestionConditionsFailed = DataDebitRequest(testBundle,
                                                      Some(failingCondition),
                                                      LocalDateTime.now(),
                                                      LocalDateTime.now().plusDays(3),
                                                      rolling = false
  )

  val ddRequestionConditionsFulfilled = DataDebitRequest(testBundle,
                                                         Some(matchingCondition),
                                                         LocalDateTime.now(),
                                                         LocalDateTime.now().plusDays(3),
                                                         rolling = false
  )
}
