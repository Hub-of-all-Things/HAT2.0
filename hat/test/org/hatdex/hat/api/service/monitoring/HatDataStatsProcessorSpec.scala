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
 * 8 / 2017
 */

package org.hatdex.hat.api.service.monitoring

import java.util.UUID

import akka.stream.Materializer
import com.google.inject.AbstractModule
import net.codingwell.scalaguice.ScalaModule
import org.hatdex.hat.api.models.{ EndpointData, Owner }
import org.hatdex.hat.api.service.applications.{ TestApplicationProvider, TrustedApplicationProvider }
import org.hatdex.hat.api.service.monitoring.HatDataEventBus.DataCreatedEvent
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.resourceManagement.FakeHatConfiguration
import org.joda.time.DateTime
import org.specs2.specification.Scope
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.json.{ JsValue, Json }
import play.api.{ Application, Logger }

import org.scalatest._
import matchers.should._
import flatspec._

class HatDataStatsProcessorSpec extends AnyFlatSpec with Matchers with HatDataStatsProcessorContext {

  val logger = Logger(this.getClass)

  "The `computeInboundStats` method" should "Correctly count numbers of values for simple objects" in {
    val service = application.injector.instanceOf[HatDataStatsProcessor]
    val stats   = service.computeInboundStats(simpleDataCreatedEvent)

    import org.hatdex.hat.api.json.DataStatsFormat._
    logger.debug(s"Got back stats: ${Json.prettyPrint(Json.toJson(stats))}")

    stats.logEntry should equal("test item")
    stats.statsType should equal("inbound")
    stats.stats.length should equal(1)
    val endpointStats = stats.stats.head
    endpointStats.endpoint should equal("testendpoint")

    endpointStats.propertyStats("field") should equal(1)
    endpointStats.propertyStats("date") should equal(1)
    endpointStats.propertyStats("date_iso") should equal(1)
    endpointStats.propertyStats("anotherField") should equal(1)
    endpointStats.propertyStats("object.objectField") should equal(1)
    endpointStats.propertyStats("object.objectFieldArray[]") should equal(3)
    endpointStats.propertyStats("object.objectFieldObjectArray[].subObjectName") should equal(2)
    endpointStats.propertyStats("object.objectFieldObjectArray[].subObjectName2") should equal(2)
  }
}

trait HatDataStatsProcessorContext extends Scope {
  import scala.concurrent.ExecutionContext.Implicits.global
  // Setup default users for testing
  val owner = HatUser(UUID.randomUUID(), "hatuser", Some("pa55w0rd"), "hatuser", Seq(Owner()), enabled = true)

  class ExtrasModule extends AbstractModule with ScalaModule {
    override def configure(): Unit =
      bind[TrustedApplicationProvider].toInstance(new TestApplicationProvider(Seq()))
  }

  lazy val application: Application = new GuiceApplicationBuilder()
    .configure(FakeHatConfiguration.config)
    .overrides(new ExtrasModule)
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

  val simpleDataCreatedEvent = DataCreatedEvent(
    "testhat.hubofallthings.net",
    ModelTranslation.fromInternalModel(owner).clean,
    DateTime.now(),
    "test item",
    Seq(EndpointData("testendpoint", Option(UUID.randomUUID()), None, None, simpleJson, None))
  )
}
