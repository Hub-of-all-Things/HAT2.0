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
 * 2 / 2017
 */

package org.hatdex.hat.phata.controllers

import scala.concurrent.Await
import scala.concurrent.duration._

import com.mohiva.play.silhouette.test._
import io.dataswift.test.common.BaseSpec
import org.hatdex.hat.api.HATTestContext
import io.dataswift.models.hat.EndpointData
import org.hatdex.hat.api.service.richData.RichDataService
import org.scalatest.{ BeforeAndAfterAll, BeforeAndAfterEach }
import play.api.Logger
import play.api.libs.json.Json
import play.api.test.Helpers._
import play.api.test.{FakeRequest, Helpers}

class PhataSpec extends BaseSpec with BeforeAndAfterEach with BeforeAndAfterAll with PhataContext {

  import scala.concurrent.ExecutionContext.Implicits.global
  val logger = Logger(this.getClass)

  import io.dataswift.models.hat.json.RichDataJsonFormats._

  override def beforeAll: Unit =
    Await.result(databaseReady, 60.seconds)

  override def afterAll() =
    container.stop()

  override def beforeEach: Unit = {
    import org.hatdex.hat.dal.Tables._
    import org.hatdex.libs.dal.HATPostgresProfile.api._

    val endpointRecrodsQuery = DataJson.filter(d => d.source.like("test%") || d.source.like("rumpel%")).map(_.recordId)

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

  "The `profile` method" should "Return bundle data with profile information" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller  = application.injector.instanceOf[Phata]
    val dataService = application.injector.instanceOf[RichDataService]

    val data = List(
      EndpointData("rumpel/notablesv1", None, None, None, samplePublicNotable, None),
      EndpointData("rumpel/notablesv1", None, None, None, samplePrivateNotable, None),
      EndpointData("rumpel/notablesv1", None, None, None, sampleSocialNotable, None)
    )

    val result = for {
      _ <- dataService.saveData(owner.userId, data)
      response <- Helpers.call(controller.profile, request)
    } yield response

    status(result) must equal(OK)
    val phataData = contentAsJson(result).as[Map[String, Seq[EndpointData]]]

    phataData.get("notables") must not be empty
    phataData("notables").length must equal(1)
  }

  // the launcher function was removed from Phata.
  // TODO: rewrite
  // "The `launcher` method" should "return status 401 if authenticator but no identity was found" in new PhataContext {
  //   val request = FakeRequest("GET", "http://hat.hubofallthings.net")
  //     .withAuthenticator(LoginInfo("xing", "comedian@watchmen.com"))

  //   val controller = application.injector.instanceOf[Phata]
  //   val result     = Helpers.call(controller.profile, request)

  //   status(result) must equal(UNAUTHORIZED)
  // }

  // it should "return OK if authenticator for matching identity" in new PhataContext {
  //   val request = FakeRequest("GET", "http://hat.hubofallthings.net")
  //     .withAuthenticator(owner.loginInfo)

  //   val controller = application.injector.instanceOf[Phata]
  //   val result     = Helpers.call(controller.profile, request)

  //   status(result) must equal(OK)
  //   //contentAsString(result) must contain("MarketSquare")
  //   //contentAsString(result) must contain("Rumpel")
  // }
}

trait PhataContext extends HATTestContext {

  val samplePublicNotable = Json.parse("""
      |{
      |    "kind": "note",
      |    "author":
      |    {
      |        "phata": "testing.hubat.net"
      |    },
      |    "shared": true,
      |    "message": "public message",
      |    "shared_on": "phata",
      |    "created_time": "2017-10-18T15:32:43+01:00",
      |    "public_until": "",
      |    "updated_time": "2017-10-23T18:29:59+01:00"
      |}
    """.stripMargin)

  val samplePrivateNotable = Json.parse("""
      |{
      |    "kind": "note",
      |    "author":
      |    {
      |        "phata": "testing.hubat.net"
      |    },
      |    "shared": false,
      |    "message": "private message",
      |    "shared_on": "marketsquare",
      |    "created_time": "2017-10-18T15:32:43+01:00",
      |    "public_until": "",
      |    "updated_time": "2017-10-23T18:29:59+01:00"
      |}
    """.stripMargin)

  val sampleSocialNotable = Json.parse("""
      |{
      |    "kind": "note",
      |    "author":
      |    {
      |        "phata": "testing.hubat.net"
      |    },
      |    "shared": true,
      |    "message": "social message",
      |    "shared_on": "facebook,twitter",
      |    "created_time": "2017-10-18T15:32:43+01:00",
      |    "public_until": "",
      |    "updated_time": "2017-10-23T18:29:59+01:00"
      |}
    """.stripMargin)
}
