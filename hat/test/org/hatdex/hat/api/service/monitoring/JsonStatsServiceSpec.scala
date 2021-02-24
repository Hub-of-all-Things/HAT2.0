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
 * 4 / 2017
 */

package org.hatdex.hat.api.service.monitoring

import java.util.UUID

import akka.stream.Materializer
import io.dataswift.test.common.BaseSpec
import io.dataswift.models.hat.{ EndpointData, Owner }
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.resourceManagement.FakeHatConfiguration
import org.scalatest.{ BeforeAndAfter, BeforeAndAfterAll }
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.json.{ JsValue, Json }
import play.api.{ Application, Logger }

class JsonStatsServiceSpec extends BaseSpec with BeforeAndAfter with BeforeAndAfterAll with JsonStatsServiceContext {

  val logger = Logger(this.getClass)

  "The `countJsonPaths` method" should "Correctly count numbers of values for simple objects" in {
    val result = JsonStatsService.countJsonPaths(simpleJson)
    result("field") must equal(1)
    result("date") must equal(1)
    result("date_iso") must equal(1)
    result("anotherField") must equal(1)
    result("object.objectField") must equal(1)
    result("object.objectFieldArray[]") must equal(3)
    result("object.objectFieldObjectArray[].subObjectName") must equal(2)
    result("object.objectFieldObjectArray[].subObjectName2") must equal(2)
  }

  "The `countEndpointData` method" should "Correctly count numbers of values for simple endpoint data objects" in {

    val counts = JsonStatsService.countEndpointData(EndpointData("test", None, None, None, simpleJson, None))
    val result = counts("test")
    result("field") must equal(1)
    result("date") must equal(1)
    result("date_iso") must equal(1)
    result("anotherField") must equal(1)
    result("object.objectField") must equal(1)
    result("object.objectFieldArray[]") must equal(3)
    result("object.objectFieldObjectArray[].subObjectName") must equal(2)
    result("object.objectFieldObjectArray[].subObjectName2") must equal(2)
  }

  it should "Correctly count numbers of values for linked endpoint data objects" in {

    val counts = JsonStatsService.countEndpointData(
      EndpointData("test",
                   None,
                   None,
                   None,
                   simpleJson,
                   Some(Seq(EndpointData("test", None, None, None, simpleJson, None)))
      )
    )
    val result = counts("test")
    result("field") must equal(2)
    result("date") must equal(2)
    result("date_iso") must equal(2)
    result("anotherField") must equal(2)
    result("object.objectField") must equal(2)
    result("object.objectFieldArray[]") must equal(6)
    result("object.objectFieldObjectArray[].subObjectName") must equal(4)
    result("object.objectFieldObjectArray[].subObjectName2") must equal(4)
  }

  "The `endpointDataCounts` method" should "correctly combine numbers of values from subsequent EndpointData records" in {

    val counts = JsonStatsService.endpointDataCounts(
      Seq(
        EndpointData("test",
                     None,
                     None,
                     None,
                     simpleJson,
                     Some(Seq(EndpointData("test", None, None, None, simpleJson, None)))
        ),
        EndpointData("test", None, None, None, simpleJson, None)
      )
    )

    counts.headOption must not be empty
    val result = counts.head.propertyStats

    result("field") must equal(3)
    result("date") must equal(3)
    result("date_iso") must equal(3)
    result("anotherField") must equal(3)
    result("object.objectField") must equal(3)
    result("object.objectFieldArray[]") must equal(9)
    result("object.objectFieldObjectArray[].subObjectName") must equal(6)
    result("object.objectFieldObjectArray[].subObjectName2") must equal(6)
  }

}

trait JsonStatsServiceContext {
  // Setup default users for testing
  val owner = HatUser(UUID.randomUUID(), "hatuser", Some("pa55w0rd"), "hatuser", Seq(Owner()), enabled = true)

  lazy val application: Application = new GuiceApplicationBuilder()
    .configure(FakeHatConfiguration.config)
    .build()

  implicit lazy val materializer: Materializer = application.materializer

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
}
