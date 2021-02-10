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

import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, HatServer }
import scala.concurrent.duration._
import scala.concurrent.{ Await }
import org.scalatest._
import matchers.should._
import flatspec._
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.{ Logger, Application => PlayApplication }
import play.api.test.Helpers
import play.api.test.FakeRequest
import play.api.libs.json.{ JsArray, JsObject, JsValue, Json }
import org.hatdex.hat.api.HATTestContext
import akka.stream.Materializer

class ContractDataSpec extends AnyFlatSpec with Matchers with ContractDataContext {

  val logger = Logger(this.getClass)
  import scala.concurrent.ExecutionContext.Implicits.global
  val application: PlayApplication = new GuiceApplicationBuilder()
    .configure(FakeHatConfiguration.config)
    .build()

  implicit lazy val materializer: Materializer = application.materializer

  "The Save Contract method" should "Return 400 on an empty request" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withBody(emptyRequestBody)

    val controller = application.injector.instanceOf[ContractData]
    val action1    = controller.createContractData("samplecontract", "testendpoint", None)
    val action2    = controller.readContractData("samplecontract", "testendpoint", None, None, None, None)

    val response = for {
      _ <- Helpers.call(action1, request)
      r <- Helpers.call(action2, request)
    } yield r

    val res = Await.result(response, 5.seconds)
    res.header.status should equal(400)
  }

  "The Read Contract Data method" should "Return 400 on an empty request" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withBody(emptyRequestBody)

    val controller = application.injector.instanceOf[ContractData]

    val response =
      Helpers.call(controller.readContractData("samplecontract", "testendpoint", None, None, None, None), request)

    val res = Await.result(response, 5.seconds)
    res.header.status should equal(400)
  }

  "The Update Contract Data method" should "Return 400 on an empty request" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withBody(emptyRequestBody)

    val controller = application.injector.instanceOf[ContractData]

    val response =
      Helpers.call(controller.readContractData("samplecontract", "testendpoint", None, None, None, None), request)

    val res = Await.result(response, 5.seconds)
    res.header.status should equal(400)
  }
}

trait ContractDataContext {
  val emptyRequestBody: JsValue = Json.parse("""{"token":"", "contractId":"", "hatName":"","body":""}""")
}
