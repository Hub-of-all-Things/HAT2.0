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

import java.util.UUID

import akka.stream.scaladsl.Sink
import org.hatdex.hat.api.HATTestContext
import org.hatdex.hat.api.models._
import org.hatdex.hat.dal.Tables.{ DataJson, DataJsonGroups }
import org.hatdex.libs.dal.HATPostgresProfile.api._
import org.specs2.concurrent.ExecutionEnv
import org.specs2.mock.Mockito
import org.specs2.specification.{ BeforeAll, BeforeEach }
import play.api.Logger
import play.api.libs.json.{ JsObject, JsValue, Json }
import play.api.test.PlaySpecification

import scala.concurrent.duration._
import scala.concurrent.{ Await, Future }

// class RichDataStreamingServiceSpec(implicit ee: ExecutionEnv) extends PlaySpecification with Mockito with RichDataServiceContext with BeforeEach with BeforeAll {
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

//   "The `propertyDataStreaming` method" should {
//     "Find test endpoint values and map them to expected json output" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- service.propertyDataStreaming(List(EndpointQuery("test/test", Some(simpleTransformation), None, None)), Some("data.newField"), false, 0, Some(1)).runWith(Sink.seq)
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(1)
//         (result.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldDifferentValue")
//       } await (3, 10.seconds)
//     }

//     "Correctly sort retrieved results" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- service.propertyDataStreaming(
//           List(
//             EndpointQuery("test/test", Some(simpleTransformation), None, None),
//             EndpointQuery("test/complex", Some(complexTransformation), None, None)),
//           Some("data.newField"), false, 0, Some(3)).runWith(Sink.seq)
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(3)
//         (result(0).data \ "data" \ "newField").as[String] must equalTo("anotherFieldDifferentValue")
//         (result(1).data \ "data" \ "newField").as[String] must equalTo("anotherFieldValue")
//         (result(2).data \ "data" \ "newField").as[String] must equalTo("london, uk")
//       } await (3, 10.seconds)
//     }

//     "Apply different mappers converting from different endpoints into a single format" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- service.propertyDataStreaming(
//           List(
//             EndpointQuery("test/test", Some(simpleTransformation), None, None),
//             EndpointQuery("test/complex", Some(complexTransformation), None, None)),
//           Some("data.newField"), false, 0, Some(3)).runWith(Sink.seq)
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(3)
//         (result.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldDifferentValue")
//       } await (3, 10.seconds)
//     }

//     "Retrieved linked object records" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, linkedSampleData)
//         retrieved <- service.propertyDataStreaming(
//           List(EndpointQuery("test/test", Some(simpleTransformation), None,
//             Some(List(
//               EndpointQuery("test/testlinked", None, None, None),
//               EndpointQuery("test/complex", None, None, None))))),
//           Some("data.newField"), false, 0, Some(1)).runWith(Sink.seq)
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(1)
//         (result.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldValue")
//         result.head.links must beSome
//         result.head.links.get.length must equalTo(2)
//         result.head.links.get(0).endpoint must equalTo("test/testlinked")
//         result.head.links.get(1).endpoint must equalTo("test/complex")
//       } await (3, 10.seconds)
//     }

//     "Leave out unrequested object records" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, linkedSampleData)
//         retrieved <- service.propertyDataStreaming(
//           List(EndpointQuery("test/test", Some(simpleTransformation), None,
//             Some(List(EndpointQuery("test/testlinked", None, None, None))))),
//           Some("data.newField"), false, 0, Some(1)).runWith(Sink.seq)
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(1)
//         (result.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldValue")
//         result.head.links must beSome
//         result.head.links.get.length must equalTo(1)
//         (result.head.links.get.head.data \ "field").as[String] must equalTo("value2")
//       } await (3, 10.seconds)
//     }

//     "Apply mappers to linked objects if provided" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, linkedSampleData)
//         retrieved <- service.propertyDataStreaming(
//           List(EndpointQuery("test/test", Some(simpleTransformation), None,
//             Some(List(EndpointQuery("test/testlinked", Some(simpleTransformation), None, None))))),
//           Some("data.newField"), false, 0, Some(1)).runWith(Sink.seq)
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(1)
//         (result.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldValue")
//         result.head.links must beSome
//         result.head.links.get.length must equalTo(1)
//         (result.head.links.get.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldDifferentValue")
//       } await (3, 10.seconds)
//     }
//   }

// }

// class RichDataServiceSpec(implicit ee: ExecutionEnv) extends PlaySpecification with Mockito with RichDataServiceContext with BeforeEach with BeforeAll {

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

//   "The `saveData` method" should {
//     "Save a single JSON datapoint and add ID" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val saved = service.saveData(owner.userId, List(EndpointData("test/test", None, None, None, simpleJson, None)))

//       saved map { record =>
//         record.length must equalTo(1)
//         record.head.recordId must beSome
//       } await (3, 10.seconds)
//     }

//     "Save multiple JSON datapoints" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val saved = service.saveData(owner.userId, sampleData)

//       saved map { record =>
//         record.length must equalTo(3)
//       } await (3, 10.seconds)
//     }

//     "Refuse to save data with duplicate records" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val saved = for {
//         _ <- service.saveData(owner.userId, List(EndpointData("test/test", None, None, None, simpleJson, None)))
//         saved <- service.saveData(owner.userId, sampleData)
//       } yield saved

//       saved must throwA[Exception].await(3, 10.seconds)
//     }

//     "Save linked JSON datapoints" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val data = List(
//         EndpointData("test/test", None, None, None, simpleJson,
//           Some(List(EndpointData("test/test", None, None, None, simpleJson2, None)))))
//       val saved = service.saveData(owner.userId, data)

//       saved map { record =>
//         record.length must equalTo(1)
//         record.head.links must beSome
//         record.head.links.get.length must equalTo(1)
//         (record.head.links.get.head.data \ "field").as[String] must equalTo("value2")
//       } await (3, 10.seconds)
//     }
//   }

//   "The `propertyData` method" should {
//     "Find test endpoint values and map them to expected json output" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- service.propertyData(List(EndpointQuery("test/test", Some(simpleTransformation), None, None)), Some("data.newField"), false, 0, Some(1))
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(1)
//         (result.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldDifferentValue")
//       } await (3, 10.seconds)
//     }

//     "Correctly sort retrieved results" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- service.propertyData(
//           List(
//             EndpointQuery("test/test", Some(simpleTransformation), None, None),
//             EndpointQuery("test/complex", Some(complexTransformation), None, None)),
//           Some("data.newField"), false, 0, Some(3))
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(3)
//         (result(0).data \ "data" \ "newField").as[String] must equalTo("anotherFieldDifferentValue")
//         (result(1).data \ "data" \ "newField").as[String] must equalTo("anotherFieldValue")
//         (result(2).data \ "data" \ "newField").as[String] must equalTo("london, uk")
//       } await (3, 10.seconds)
//     }

//     "Apply different mappers converting from different endpoints into a single format" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- service.propertyData(
//           List(
//             EndpointQuery("test/test", Some(simpleTransformation), None, None),
//             EndpointQuery("test/complex", Some(complexTransformation), None, None)),
//           Some("data.newField"), false, 0, Some(3))
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(3)
//         (result.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldDifferentValue")
//       } await (3, 10.seconds)
//     }

//     "Retrieved linked object records" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, linkedSampleData)
//         retrieved <- service.propertyData(
//           List(EndpointQuery("test/test", Some(simpleTransformation), None,
//             Some(List(
//               EndpointQuery("test/testlinked", None, None, None),
//               EndpointQuery("test/complex", None, None, None))))),
//           Some("data.newField"), false, 0, Some(1))
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(1)
//         (result.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldValue")
//         result.head.links must beSome
//         result.head.links.get.length must equalTo(2)
//         result.head.links.get(0).endpoint must equalTo("test/testlinked")
//         result.head.links.get(1).endpoint must equalTo("test/complex")
//       } await (3, 10.seconds)
//     }

//     "Leave out unrequested object records" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, linkedSampleData)
//         retrieved <- service.propertyData(
//           List(EndpointQuery("test/test", Some(simpleTransformation), None,
//             Some(List(EndpointQuery("test/testlinked", None, None, None))))),
//           Some("data.newField"), false, 0, Some(1))
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(1)
//         (result.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldValue")
//         result.head.links must beSome
//         result.head.links.get.length must equalTo(1)
//         (result.head.links.get.head.data \ "field").as[String] must equalTo("value2")
//       } await (3, 10.seconds)
//     }

//     "Apply mappers to linked objects if provided" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         _ <- service.saveData(owner.userId, linkedSampleData)
//         retrieved <- service.propertyData(
//           List(EndpointQuery("test/test", Some(simpleTransformation), None,
//             Some(List(EndpointQuery("test/testlinked", Some(simpleTransformation), None, None))))),
//           Some("data.newField"), false, 0, Some(1))
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(1)
//         (result.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldValue")
//         result.head.links must beSome
//         result.head.links.get.length must equalTo(1)
//         (result.head.links.get.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldDifferentValue")
//       } await (3, 10.seconds)
//     }
//   }

//   "The `saveRecordGroup` method" should {
//     "Link up inserted records for retrieval" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         saved <- service.saveData(owner.userId, sampleData)
//         linked <- service.saveRecordGroup(owner.userId, saved.flatMap(_.recordId))
//         retrieved <- service.propertyData(
//           List(EndpointQuery("test/test", Some(simpleTransformation), None,
//             Some(List(
//               EndpointQuery("test/test", None, None, None),
//               EndpointQuery("test/complex", None, None, None))))),
//           Some("data.newField"), false, 0, Some(3))
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(2)
//         (result.head.data \ "data" \ "newField").as[String] must equalTo("anotherFieldDifferentValue")
//         result.head.links must beSome
//         result.head.links.get.length must equalTo(2)
//         result.head.links.get(0).endpoint must equalTo("test/test")
//         result.head.links.get(1).endpoint must equalTo("test/complex")
//       } await (3, 10.seconds)
//     }

//     "Throw an error if linked records do not exist" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         linked <- service.saveRecordGroup(owner.userId, Seq(UUID.randomUUID(), UUID.randomUUID()))
//       } yield linked

//       result must throwA[Exception].await(3, 10.seconds)
//     }
//   }

//   "The `generatedDataQuery` method" should {

//     import org.hatdex.libs.dal.HATPostgresProfile.api._

//     "retrieve all results without any additional filters" in {
//       val service = application.injector.instanceOf[RichDataService]
//       val query = service.generatedDataQuery(EndpointQuery("test/test", None, None, None), DataJson)

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- hatDatabase.run(query.result)
//       } yield retrieved

//       result map { retrievedRows =>
//         retrievedRows.length should equalTo(2)
//       } await (3, 10.seconds)
//     }

//     "retrieve results with a `Contains` filter " in {
//       val service = application.injector.instanceOf[RichDataService]
//       val query = service.generatedDataQuery(EndpointQuery("test/test", None,
//         Some(Seq(
//           EndpointQueryFilter("object.objectFieldArray", None, FilterOperator.Contains(Json.toJson("objectFieldArray2"))))), None), DataJson)

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- hatDatabase.run(query.result)
//       } yield retrieved

//       result map { retrievedRows =>
//         retrievedRows.length should equalTo(2)
//       } await (3, 10.seconds)
//     }

//     "retrieve results with a `Contains` filter for complex objects " in {
//       val service = application.injector.instanceOf[RichDataService]
//       val query = service.generatedDataQuery(EndpointQuery("test/test", None,
//         Some(Seq(
//           EndpointQueryFilter("object", None, FilterOperator.Contains(simpleJsonFragment)))), None), DataJson)

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- hatDatabase.run(query.result)
//       } yield retrieved

//       result map { retrievedRows =>
//         retrievedRows.length should equalTo(2)
//       } await (3, 10.seconds)
//     }

//     "use `Contains` filter for equality" in {
//       val service = application.injector.instanceOf[RichDataService]
//       val query = service.generatedDataQuery(EndpointQuery("test/test", None,
//         Some(Seq(
//           EndpointQueryFilter("field", None, FilterOperator.Contains(Json.toJson("value2"))))), None), DataJson)

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- hatDatabase.run(query.result)
//       } yield retrieved

//       result map { retrievedRows =>
//         retrievedRows.length should equalTo(1)
//         (retrievedRows.head.data \ "anotherField").as[String] must equalTo("anotherFieldDifferentValue")
//       } await (3, 10.seconds)
//     }

//     "retrieve results with a `Between` filter" in {
//       val service = application.injector.instanceOf[RichDataService]
//       val query = service.generatedDataQuery(EndpointQuery("test/test", None,
//         Some(Seq(
//           EndpointQueryFilter("date", None, FilterOperator.Between(Json.toJson(1492699000), Json.toJson(1492799000))))), None), DataJson)

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- hatDatabase.run(query.result)
//       } yield retrieved

//       result map { retrievedRows =>
//         retrievedRows.length should equalTo(1)
//         (retrievedRows.head.data \ "anotherField").as[String] must equalTo("anotherFieldValue")
//       } await (3, 10.seconds)
//     }

//     "Use the `In` filter for a 'one-of' matching " in {
//       val service = application.injector.instanceOf[RichDataService]
//       val query = service.generatedDataQuery(EndpointQuery("test/test", None,
//         Some(Seq(
//           EndpointQueryFilter("field", None, FilterOperator.In(Json.parse("""["value", "value2"]"""))))), None), DataJson)

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- hatDatabase.run(query.result)
//       } yield retrieved

//       result map { retrievedRows =>
//         retrievedRows.length should equalTo(2)
//       } await (3, 10.seconds)
//     }

//     "Use transformation operator for date conversion combined with a `Between` filter" in {
//       val service = application.injector.instanceOf[RichDataService]
//       val query = service.generatedDataQuery(EndpointQuery("test/test", None,
//         Some(Seq(
//           EndpointQueryFilter(
//             "date_iso",
//             Some(FieldTransformation.DateTimeExtract("hour")),
//             FilterOperator.Between(Json.toJson(14), Json.toJson(17))))), None), DataJson)

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- hatDatabase.run(query.result)
//       } yield retrieved

//       result map { retrievedRows =>
//         retrievedRows.length should equalTo(1)
//         (retrievedRows.head.data \ "anotherField").as[String] must equalTo("anotherFieldValue")
//       } await (3, 10.seconds)
//     }

//     "Use transformation operator for unix timestamp conversion combined with a `Between` filter" in {
//       val service = application.injector.instanceOf[RichDataService]
//       val query = service.generatedDataQuery(EndpointQuery("test/test", None,
//         Some(Seq(
//           EndpointQueryFilter(
//             "date",
//             Some(FieldTransformation.TimestampExtract("hour")),
//             FilterOperator.Between(Json.toJson(14), Json.toJson(17))))), None), DataJson)

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- hatDatabase.run(query.result)
//       } yield retrieved

//       result map { retrievedRows =>
//         retrievedRows.length should equalTo(1)
//         (retrievedRows.head.data \ "anotherField").as[String] must equalTo("anotherFieldValue")
//       } await (3, 10.seconds)
//     }

//     "Run search with a `Find` filter" in {
//       val service = application.injector.instanceOf[RichDataService]
//       val query = service.generatedDataQuery(EndpointQuery("test/complex", None,
//         Some(Seq(
//           EndpointQueryFilter(
//             "hometown.name",
//             None,
//             FilterOperator.Find(Json.toJson("london"))))), None), DataJson)

//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- hatDatabase.run(query.result)
//       } yield retrieved

//       result map { retrievedRows =>
//         retrievedRows.length should equalTo(1)
//         (retrievedRows.head.data \ "email").as[String] must equalTo("email@example.com")
//       } await (3, 10.seconds)
//     }
//   }

//   "The `bundleData` method" should {
//     "retrieve values into corresponding properties" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val query = EndpointDataBundle("testBundle", Map(
//         "test" -> PropertyQuery(List(EndpointQuery("test/test", Some(simpleTransformation), None, None)), Some("data.newField"), None, Some(3)),
//         "complex" -> PropertyQuery(List(EndpointQuery("test/complex", Some(complexTransformation), None, None)), Some("data.newField"), None, Some(1))))
//       val result = for {
//         _ <- service.saveData(owner.userId, sampleData)
//         retrieved <- service.bundleData(query)
//       } yield retrieved

//       result map { result =>
//         result.size must equalTo(2)
//         result.get("test") must beSome
//         result.get("complex") must beSome
//         result("test").length must equalTo(2)
//         (result("test")(0).data \ "data" \ "newField").as[String] must equalTo("anotherFieldDifferentValue")
//         result("complex").length must equalTo(1)
//         (result("complex")(0).data \ "data" \ "newField").as[String] must equalTo("london, uk")
//       } await (3, 10.seconds)
//     }
//   }

//   "The `deleteRecords` method" should {
//     "delete all required records" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         saved <- service.saveData(owner.userId, sampleData)
//         deleted <- service.deleteRecords(owner.userId, Seq(saved(1).recordId.get))
//         retrieved <- service.propertyData(
//           List(
//             EndpointQuery("test/test", Some(simpleTransformation), None, None),
//             EndpointQuery("test/complex", Some(complexTransformation), None, None)),
//           Some("data.newField"), false, 0, Some(3))
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(2)
//         (result(0).data \ "data" \ "newField").as[String] must equalTo("anotherFieldValue")
//         (result(1).data \ "data" \ "newField").as[String] must equalTo("london, uk")
//       } await (3, 10.seconds)
//     }

//     "not delete any records if some requested records do not exist" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         saved <- service.saveData(owner.userId, sampleData)
//         _ <- service.deleteRecords(owner.userId, Seq(saved(1).recordId.get, UUID.randomUUID())).recover { case _ => Future.successful(()) }
//         retrieved <- service.propertyData(
//           List(
//             EndpointQuery("test/test", Some(simpleTransformation), None, None),
//             EndpointQuery("test/complex", Some(complexTransformation), None, None)),
//           Some("data.newField"), false, 0, Some(3))
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(3)
//       } await (3, 10.seconds)
//     }

//     "not delete records if provided user Id doesn't match" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         saved <- service.saveData(owner.userId, sampleData)
//         deleted <- service.deleteRecords(dataDebitUser.userId, Seq(saved(1).recordId.get))
//       } yield deleted

//       result must throwA[Exception].await(3, 10.seconds)
//     }

//     "delete groups if all records in those groups are deleted" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         saved <- service.saveData(owner.userId, linkedSampleData)
//         deleted <- service.deleteRecords(owner.userId, saved.head.links.get.map(_.recordId.get) :+ saved.head.recordId.get)
//         groups <- hatDatabase.run(DataJsonGroups.take(1).result)
//       } yield groups

//       result map { groups =>
//         groups.isEmpty must beTrue
//       } await (3, 10.seconds)
//     }
//   }

//   "The `updateRecords` method" should {
//     "update all required records" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         saved <- service.saveData(owner.userId, sampleData)
//         updated <- service.updateRecords(owner.userId, Seq(saved(1).copy(data = simpleJson2Updated)))
//         retrieved <- service.propertyData(
//           List(
//             EndpointQuery("test/test", Some(simpleTransformation), None, None),
//             EndpointQuery("test/complex", Some(complexTransformation), None, None)),
//           Some("data.newField"), false, 0, Some(3))
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(3)
//         (result(0).data \ "data" \ "newField").as[String] must equalTo("aaa")
//         (result(1).data \ "data" \ "newField").as[String] must equalTo("anotherFieldValue")
//         (result(2).data \ "data" \ "newField").as[String] must equalTo("london, uk")
//       } await (3, 10.seconds)
//     }

//     "not update any records if some requested records do not exist" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val data = List(
//         EndpointData("test/test", None, None, None, simpleJson, None),
//         EndpointData("test/test", None, None, None, simpleJson2, None))

//       val result = for {
//         saved <- service.saveData(owner.userId, data)
//         _ <- service.updateRecords(owner.userId, Seq(
//           saved(1).copy(data = simpleJson2Updated),
//           EndpointData("test/complex", None, None, None, complexJson, None))).recover { case _ => Future.successful(()) }
//         retrieved <- service.propertyData(
//           List(
//             EndpointQuery("test/test", Some(simpleTransformation), None, None),
//             EndpointQuery("test/complex", Some(complexTransformation), None, None)),
//           Some("data.newField"), false, 0, Some(3))
//       } yield retrieved

//       result map { result =>
//         result.length must equalTo(2)
//         (result(0).data \ "data" \ "newField").as[String] must equalTo("anotherFieldDifferentValue")
//         (result(1).data \ "data" \ "newField").as[String] must equalTo("anotherFieldValue")
//       } await (3, 10.seconds)
//     }

//     "not update records if provided user Id doesn't match" in {
//       val service = application.injector.instanceOf[RichDataService]

//       val result = for {
//         saved <- service.saveData(owner.userId, sampleData)
//         deleted <- service.updateRecords(dataDebitUser.userId, Seq(saved(1).copy(data = simpleJson2Updated)))
//       } yield deleted

//       result must throwA[Exception].await(3, 10.seconds)
//     }
//   }
// }

trait RichDataServiceContext { //extends HATTestContext {
  val simpleJson: JsValue = Json.parse("""
      | {
      |   "field": "value",
      |   "testUniqueID": "1234567",
      |   "date": 1492699047,
      |   "date_ms": 1492699047000,
      |   "date_iso": "2017-04-20T14:37:27+00:00",
      |   "anotherField": "anotherFieldValue",
      |   "object": {
      |     "objectField": "objectFieldValue",
      |     "nestedInfo": {
      |       "deeplyLocatedUniqueId": "7654321"
      |     },
      |     "objectFieldArray": ["objectFieldArray1", "objectFieldArray2", "objectFieldArray3"],
      |     "objectFieldObjectArray": [
      |       {"subObjectName": "subObject1", "subObjectName2": "subObject1-2"},
      |       {"subObjectName": "subObject2", "subObjectName2": "subObject2-2"}
      |     ]
      |   }
      | }
    """.stripMargin)

  val simpleJsonFragment: JsValue = Json.parse("""
      | {
      |     "objectField": "objectFieldValue",
      |     "objectFieldObjectArray": [
      |       {"subObjectName": "subObject1", "subObjectName2": "subObject1-2"},
      |       {"subObjectName": "subObject2", "subObjectName2": "subObject2-2"}
      |     ]
      | }
    """.stripMargin)

  val simpleJson2: JsValue = Json.parse("""
      | {
      |   "field": "value2",
      |   "date": 1492799048,
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

  val simpleJson2Updated = Json.parse("""
      | {
      |   "field": "value2",
      |   "date": 1492799048,
      |   "date_iso": "2017-04-21T18:24:07+00:00",
      |   "anotherField": "aaa",
      |   "differentField": "new"
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

  val simpleTransformation: JsObject = Json
    .parse("""
      | {
      |   "data.newField": "anotherField",
      |   "data.arrayField": "object.objectFieldArray",
      |   "data.onemore": "object.education[1]"
      | }
    """.stripMargin)
    .as[JsObject]

  val complexTransformation: JsObject = Json
    .parse("""
      | {
      |   "data.newField": "hometown.name",
      |   "data.arrayField": "education",
      |   "data.onemore": "education[0].type"
      | }
    """.stripMargin)
    .as[JsObject]

  val sampleData = List(
    EndpointData("test/test", None, None, None, simpleJson, None),
    EndpointData("test/test", None, None, None, simpleJson2, None),
    EndpointData("test/complex", None, None, None, complexJson, None)
  )

  val linkedSampleData = List(
    EndpointData(
      "test/test",
      None,
      None,
      None,
      simpleJson,
      Some(
        List(EndpointData("test/testlinked", None, None, None, simpleJson2, None),
             EndpointData("test/complex", None, None, None, complexJson, None)
        )
      )
    )
  )
}
