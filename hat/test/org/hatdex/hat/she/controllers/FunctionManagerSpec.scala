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
 * 11 / 2017
 */

package org.hatdex.hat.she.controllers

import akka.util
import com.mohiva.play.silhouette.api.LoginInfo
import com.mohiva.play.silhouette.test._
import org.hatdex.hat.api.models.{ EndpointQuery, ErrorMessage, SuccessResponse }
import org.hatdex.hat.api.service.richData.RichDataService
import org.hatdex.hat.she.functions.DataFeedDirectMapperContext
import org.hatdex.hat.she.models.FunctionConfiguration
import org.hatdex.hat.she.service.FunctionService
import org.joda.time.DateTimeUtils
import play.api.Logger
import play.api.mvc.Result
import play.api.test.{ FakeRequest }

import scala.concurrent.duration._
import scala.concurrent.{ Await, Future }
import io.dataswift.test.common.BaseSpec
import org.scalatest.{ BeforeAndAfterAll, BeforeAndAfterEach }
import play.api.test.Helpers
import play.api.test.Helpers._

class FunctionManagerSpec
    extends BaseSpec
    with BeforeAndAfterEach
    with BeforeAndAfterAll
    with DataFeedDirectMapperContext {

  import scala.concurrent.ExecutionContext.Implicits.global
  val logger = Logger(this.getClass)

  import org.hatdex.hat.api.json.HatJsonFormats.{ errorMessage, successResponse }
  import org.hatdex.hat.she.models.FunctionConfigurationJsonProtocol._

  implicit def defaultAwaitTimeout: util.Timeout = 60.seconds

  override def beforeAll: Unit = {
    DateTimeUtils.setCurrentMillisFixed(1514764800000L)
    Await.result(databaseReady, 60.seconds)
  }

  override def afterAll: Unit = {
    DateTimeUtils.setCurrentMillisSystem()
    container.stop()
  }

  "The `functionList` method" should "return status 401 if authenticator but no identity was found" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(LoginInfo("xing", "comedian@watchmen.com"))

    val controller             = application.injector.instanceOf[FunctionManager]
    val result: Future[Result] = Helpers.call(controller.functionList(), request)

    status(result) must equal(UNAUTHORIZED)
  }

  it should "return status 403 if authenticator and existing identity but wrong role" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(dataDebitUser.loginInfo)

    val controller             = application.injector.instanceOf[FunctionManager]
    val result: Future[Result] = Helpers.call(controller.functionList(), request)

    status(result) must equal(FORBIDDEN)
  }

  it should "return list of all registered or available functions for `owner`" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller             = application.injector.instanceOf[FunctionManager]
    val result: Future[Result] = Helpers.call(controller.functionList(), request)

    status(result) must equal(OK)
    val functions = contentAsJson(result).as[Seq[FunctionConfiguration]]
    functions.length must be > 2
    val registered = functions.find(_.id == registeredDummyFunctionAvailable.configuration.id).get
    registered.status.available must equal(true)
    registered.status.enabled must equal(false)
  }

  "The `functionGet` method" should "return a specific requested function if found" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[FunctionManager]
    val result: Future[Result] =
      Helpers.call(controller.functionGet(registeredDummyFunctionAvailable.configuration.id), request)

    status(result) must equal(OK)
    val function = contentAsJson(result).as[FunctionConfiguration]
    function.status.available must equal(true)
    function.status.enabled must equal(false)
  }

  it should "return 404 if requested function not found" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller             = application.injector.instanceOf[FunctionManager]
    val result: Future[Result] = Helpers.call(controller.functionGet("random-function"), request)

    status(result) must equal(NOT_FOUND)
    val message = contentAsJson(result).as[ErrorMessage]
    message.message must equal("Function Not Found")
  }

  "The `functionEnable` method" should "Enable a specific requested function if found" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[FunctionManager]
    val chained: Future[(Result, Result)] = for {
      enabled <- Helpers.call(controller.functionEnable("data-feed-direct-mapper"), request)
      result <- Helpers.call(controller.functionGet("data-feed-direct-mapper"), request)
    } yield (enabled, result)

    val enabled = chained.map(_._1)
    val result  = chained.map(_._2)

    status(enabled) must equal(OK)
    val fEnabled = contentAsJson(result).as[FunctionConfiguration]
    fEnabled.id must equal("data-feed-direct-mapper")
    fEnabled.status.available must equal(true)
    fEnabled.status.enabled must equal(true)

    status(result) must equal(OK)
    val function = contentAsJson(result).as[FunctionConfiguration]
    function.id must equal("data-feed-direct-mapper")
    function.status.available must equal(true)
    function.status.enabled must equal(true)
  }

  it should "return 404 if requested function not found" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller             = application.injector.instanceOf[FunctionManager]
    val result: Future[Result] = Helpers.call(controller.functionEnable("random-function"), request)

    status(result) must equal(NOT_FOUND)
    val message = contentAsJson(result).as[ErrorMessage]
    message.message must equal("Function Not Found")
  }

  "The `functionDisable` method" should "Disable a specific requested function if found" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[FunctionManager]
    val chained: Future[(Result, Result)] = for {
      _ <- Helpers.call(controller.functionEnable("data-feed-direct-mapper"), request)
      disabled <- Helpers.call(controller.functionDisable("data-feed-direct-mapper"), request)
      result <- Helpers.call(controller.functionGet("data-feed-direct-mapper"), request)
    } yield (disabled, result)

    val disabled = chained.map(_._1)
    val result   = chained.map(_._2)

    status(disabled) must equal(OK)
    val fDisabled = contentAsJson(result).as[FunctionConfiguration]
    fDisabled.id must equal("data-feed-direct-mapper")
    fDisabled.status.available must equal(true)
    fDisabled.status.enabled must equal(false)

    status(result) must equal(OK)
    val function = contentAsJson(result).as[FunctionConfiguration]
    function.id must equal("data-feed-direct-mapper")
    function.status.available must equal(true)
    function.status.enabled must equal(false)
  }

  "The `functionTrigger` method" should "Respond with Not Found for a non-existing function" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller             = application.injector.instanceOf[FunctionManager]
    val result: Future[Result] = Helpers.call(controller.functionTrigger("random-function", useAll = false), request)

    status(result) must equal(NOT_FOUND)
    val message = contentAsJson(result).as[ErrorMessage]
    message.message must equal("Function Not Found")
  }

  it should "Respond with Bad Request for a non-enabled function" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller = application.injector.instanceOf[FunctionManager]
    val result: Future[Result] =
      Helpers.call(controller.functionTrigger(registeredDummyFunctionAvailable.configuration.id, useAll = false),
                   request
      )

    status(result) must equal(BAD_REQUEST)
    val message = contentAsJson(result).as[ErrorMessage]
    message.message must equal("Function Not Enabled")
  }

  it should "Respond with Bad Request for a non-available function" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val service    = application.injector.instanceOf[FunctionService]
    val controller = application.injector.instanceOf[FunctionManager]
    val result: Future[Result] = for {
      _ <- service.save(dummyFunctionConfiguration)
      result <- Helpers.call(controller.functionTrigger("test-dummy-function", useAll = false), request)
    } yield result

    status(result) must equal(BAD_REQUEST)
    val message = contentAsJson(result).as[ErrorMessage]
    message.message must equal("Function Not Available")
  }

  it should "Execute available and enabled function" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val dataService = application.injector.instanceOf[RichDataService]
    val controller  = application.injector.instanceOf[FunctionManager]

    val records = Seq(
      exampleTweetRetweet,
      exampleTweetMentions,
      exampleFacebookPhotoPost,
      exampleFacebookPost,
      facebookStory,
      facebookEvent,
      facebookEvenNoLocation,
      facebookEvenPartialLocation,
      fitbitSleepMeasurement,
      fitbitWeightMeasurement,
      fitbitActivity,
      googleCalendarEvent,
      googleCalendarFullDayEvent
    )

    val setup = for {
      _ <- dataService.saveData(owner.userId, records)
      function <- Helpers.call(controller.functionEnable("data-feed-direct-mapper"), request)
    } yield function

    await(setup)(60.seconds)

    val result = Helpers.call(controller.functionTrigger("data-feed-direct-mapper", useAll = false), request)
    status(result) must equal(OK)
    val message = contentAsJson(result).as[SuccessResponse]
    message.message must equal("Function Executed")

    dataService
      .propertyData(
        Seq(EndpointQuery(s"${registeredFunction.namespace}/${registeredFunction.endpoint}", None, None, None)),
        None,
        orderingDescending = false,
        0,
        None
      )
      .map { data =>
        data.length must be >= records.length
        data.forall(
          _.endpoint == s"${registeredFunction.namespace}/${registeredFunction.endpoint}"
        ) must equal(true)
      }
    //await (3, 60.seconds)
  }

}
