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
import org.hatdex.hat.api.models.{ Owner, _ }
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.resourceManagement.FakeHatConfiguration
import org.specs2.specification.Scope
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.json.{ JsValue, Json }
import play.api.{ Application, Logger }

import org.scalatest._
import matchers.should._
import flatspec._

class EndpointSubscriberServiceSpec extends AnyFlatSpec with Matchers with EndpointSubscriberServiceContext {

  val logger = Logger(this.getClass)

  "The `matchesBundle` method" should "Trigger when endpoint query with no filters matches" in {
    val query = EndpointDataBundle(
      "test",
      Map("test" -> PropertyQuery(List(EndpointQuery("test/test", None, None, None)), None, None, Some(3)))
    )

    EndpointSubscriberService.matchesBundle(simpleEndpointData, query) should be(true)
  }

  it should "Not trigger when endpoint no query matches" in {
    val query = EndpointDataBundle(
      "test",
      Map("test" -> PropertyQuery(List(EndpointQuery("test/anothertest", None, None, None)), None, None, Some(3)))
    )

    EndpointSubscriberService.matchesBundle(simpleEndpointData, query) should be(false)
  }

  it should "Trigger when endpoint query with `Contains` filter matches" in {
    val query = EndpointDataBundle(
      "test",
      Map(
        "test" -> PropertyQuery(
              List(
                EndpointQuery(
                  "test/test",
                  None,
                  Some(Seq(EndpointQueryFilter("object", None, FilterOperator.Contains(simpleJsonFragment)))),
                  None
                )
              ),
              None,
              None,
              Some(3)
            )
      )
    )

    EndpointSubscriberService.matchesBundle(simpleEndpointData, query) should be(true)
  }

  it should "Trigger when endpoint query with `Contains` filter matches for equality" in {
    val query = EndpointDataBundle(
      "test",
      Map(
        "test" -> PropertyQuery(
              List(
                EndpointQuery("test/test",
                              None,
                              Some(
                                Seq(
                                  EndpointQueryFilter("object.objectField",
                                                      None,
                                                      FilterOperator.Contains(Json.toJson("objectFieldValue"))
                                  )
                                )
                              ),
                              None
                )
              ),
              None,
              None,
              Some(3)
            )
      )
    )

    EndpointSubscriberService.matchesBundle(simpleEndpointData, query) should be(true)
  }

  it should "Trigger when endpoint query with `Contains` filter matches for array containment" in {
    val query = EndpointDataBundle(
      "test",
      Map(
        "test" -> PropertyQuery(
              List(
                EndpointQuery("test/test",
                              None,
                              Some(
                                Seq(
                                  EndpointQueryFilter("object.objectFieldArray",
                                                      None,
                                                      FilterOperator.Contains(Json.toJson("objectFieldArray2"))
                                  )
                                )
                              ),
                              None
                )
              ),
              None,
              None,
              Some(3)
            )
      )
    )

    EndpointSubscriberService.matchesBundle(simpleEndpointData, query) should be(true)
  }

  it should "Trigger when endpoint query with `Contains` filter matches for array intersection" in {
    val query = EndpointDataBundle(
      "test",
      Map(
        "test" -> PropertyQuery(
              List(
                EndpointQuery(
                  "test/test",
                  None,
                  Some(
                    Seq(
                      EndpointQueryFilter(
                        "object.objectFieldArray",
                        None,
                        FilterOperator.Contains(Json.parse("""["objectFieldArray2", "objectFieldArray3"]"""))
                      )
                    )
                  ),
                  None
                )
              ),
              None,
              None,
              Some(3)
            )
      )
    )

    EndpointSubscriberService.matchesBundle(simpleEndpointData, query) should be(true)
  }

  it should "Trigger when endpoint query with `DateTimeExtract` filter matches" in {
    val query = EndpointDataBundle(
      "test",
      Map(
        "test" -> PropertyQuery(
              List(
                EndpointQuery(
                  "test/test",
                  None,
                  Some(
                    Seq(
                      EndpointQueryFilter("date_iso",
                                          Some(FieldTransformation.DateTimeExtract("hour")),
                                          FilterOperator.Between(Json.toJson(14), Json.toJson(17))
                      )
                    )
                  ),
                  None
                )
              ),
              None,
              None,
              Some(3)
            )
      )
    )

    EndpointSubscriberService.matchesBundle(simpleEndpointData, query) should be(true)
  }

  it should "Trigger when endpoint query with `TimestampExtract` filter matches" in {
    val query = EndpointDataBundle(
      "test",
      Map(
        "test" -> PropertyQuery(
              List(
                EndpointQuery(
                  "test/test",
                  None,
                  Some(
                    Seq(
                      EndpointQueryFilter("date",
                                          Some(FieldTransformation.TimestampExtract("hour")),
                                          FilterOperator.Between(Json.toJson(14), Json.toJson(17))
                      )
                    )
                  ),
                  None
                )
              ),
              None,
              None,
              Some(3)
            )
      )
    )

    EndpointSubscriberService.matchesBundle(simpleEndpointData, query) should be(true)
  }

  it should "Throw an error for text search field transformation" in {
    val query = EndpointDataBundle(
      "test",
      Map(
        "test" -> PropertyQuery(
              List(
                EndpointQuery(
                  "test/test",
                  None,
                  Some(
                    Seq(
                      EndpointQueryFilter("anotherField",
                                          Some(FieldTransformation.Searchable()),
                                          FilterOperator.Find(Json.toJson("anotherFieldValue"))
                      )
                    )
                  ),
                  None
                )
              ),
              None,
              None,
              Some(3)
            )
      )
    )

    try {
      EndpointSubscriberService.matchesBundle(simpleEndpointData, query)
      fail()
    } catch {
      case (_: EndpointQueryException) =>
    }
  }
}

trait EndpointSubscriberServiceContext extends Scope {
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

  val simpleJsonFragment: JsValue = Json.parse("""
      | {
      |     "objectField": "objectFieldValue",
      |     "objectFieldObjectArray": [
      |       {"subObjectName": "subObject1", "subObjectName2": "subObject1-2"},
      |       {"subObjectName": "subObject2", "subObjectName2": "subObject2-2"}
      |     ]
      | }
    """.stripMargin)

  val simpleEndpointData = EndpointData("test/test", Some(UUID.randomUUID()), None, None, simpleJson, None)
}
