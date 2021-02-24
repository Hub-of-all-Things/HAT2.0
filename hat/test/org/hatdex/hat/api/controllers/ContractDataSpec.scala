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

import scala.concurrent.Await
import scala.concurrent.duration._

import io.dataswift.test.common.BaseSpec
import org.hatdex.hat.api.HATTestContext
import org.scalatest.{BeforeAndAfter, BeforeAndAfterAll}
import play.api.Logger
import play.api.libs.json.{JsValue, Json}
import play.api.test.Helpers._
import play.api.test.{FakeRequest, Helpers}

class ContractDataSpec extends BaseSpec with BeforeAndAfter with BeforeAndAfterAll with ContractDataContext {
  import scala.concurrent.ExecutionContext.Implicits.global

  val logger = Logger(this.getClass)

  override def beforeAll: Unit =
    Await.result(databaseReady, 60.seconds)

  override def afterAll() =
    container.stop()

  "The Save Contract method" should "Return 400 on an empty request" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withJsonBody(emptyRequestBody)

    val controller = application.injector.instanceOf[ContractData]

    val response = for {
      _ <- Helpers.call(controller.createContractData("samplecontract", "testendpoint", None), request)
      r <- Helpers.call(controller.readContractData("samplecontract", "testendpoint", None, None, None, None), request)
    } yield r

    val res = Await.result(response, 5.seconds)
    res.header.status must equal(400)
  }

  "The Read Contract Data method" should "Return 400 on an empty request" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withJsonBody(emptyRequestBody)

    val controller = application.injector.instanceOf[ContractData]

    val response =
      Helpers.call(controller.readContractData("samplecontract", "testendpoint", None, None, None, None), request)

    val res = Await.result(response, 5.seconds)
    res.header.status must equal(400)
  }

  "The Update Contract Data method" should "Return 400 on an empty request" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withJsonBody(emptyRequestBody)

    val controller = application.injector.instanceOf[ContractData]

    val response =
      Helpers.call(controller.readContractData("samplecontract", "testendpoint", None, None, None, None), request)

    val res = Await.result(response, 5.seconds)
    res.header.status must equal(400)
  }
}

trait ContractDataContext extends HATTestContext {
  val emptyRequestBody: JsValue = Json.parse("""{"token":"", "contractId":"", "hatName":"","body":""}""")
}
