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

package org.hatdex.hat.she.service

import org.hatdex.hat.api.models.EndpointQuery
import org.hatdex.hat.api.service.richData.RichDataService
import org.hatdex.hat.she.functions.DataFeedDirectMapperContext
import org.joda.time.DateTimeUtils
import play.api.Logger

import scala.concurrent.Await
import scala.concurrent.duration._
import io.dataswift.test.common.BaseSpec
import org.scalatest.{ BeforeAndAfterAll, BeforeAndAfterEach }

class FunctionServiceSpec
    extends BaseSpec
    with BeforeAndAfterEach
    with BeforeAndAfterAll
    with DataFeedDirectMapperContext {

  import scala.concurrent.ExecutionContext.Implicits.global
  val logger = Logger(this.getClass)

  override def beforeAll: Unit = {
    DateTimeUtils.setCurrentMillisFixed(1514764800000L)
    Await.result(databaseReady, 60.seconds)
  }

  override def afterAll: Unit = {
    DateTimeUtils.setCurrentMillisSystem()
    container.stop()
  }

  override def before(): Unit = {
    import org.hatdex.hat.dal.Tables._
    import org.hatdex.libs.dal.HATPostgresProfile.api._

    val endpointRecordsQuery = DataJson.filter(_.source.like("test%")).map(_.recordId)

    val action = DBIO.seq(
      DataBundles.filter(_.bundleId.like("test%")).delete,
      SheFunction.filter(_.id.like("test%")).delete,
      DataJsonGroupRecords.filter(_.recordId in endpointRecordsQuery).delete,
      DataJsonGroups.filterNot(g => g.groupId in DataJsonGroupRecords.map(_.groupId)).delete,
      DataJson.filter(r => r.recordId in endpointRecordsQuery).delete
    )

    Await.result(db.run(action), 60.seconds)
  }

  "The `get` method" should "return `None` when no such function exists" in {
    val service = application.injector.instanceOf[FunctionService]
    val r       = service.get("non-existing-function")
    Await.result(r, 10.seconds)
    r === None
  }

  it should "return saved function by name" in {
    val service = application.injector.instanceOf[FunctionService]

    val saved = for {
      _ <- service.save(unavailableFunctionConfiguration)
      saved <- service.get(unavailableFunctionConfiguration.id)
    } yield saved

    saved
      .map { mSaved =>
        mSaved must not be empty
        val c = mSaved.get
        c.id must equal(unavailableFunctionConfiguration.id)
        c.status.available must equal(false)
      }
    Await.result(saved, 10.seconds)
  }

  it should "return available, not saved function by name" in {
    val service = application.injector.instanceOf[FunctionService]

    val saved = for {
      _ <- service.save(dummyFunctionConfiguration)
      available <- service.get(registeredFunction.configuration.id)
    } yield available

    saved
      .map { mAvailable =>
        mAvailable must not be empty
        val c2 = mAvailable.get
        c2.id must equal(registeredFunction.configuration.id)
        c2.status.available must equal(true)
      }
    Await.result(saved, 10.seconds)
  }

  "The `saved` method" should "List saved functions only" in {
    val service = application.injector.instanceOf[FunctionService]

    val all = for {
      _ <- service.save(unavailableFunctionConfiguration)
      all <- service.saved()
    } yield all

    all
      .map { functions =>
        functions.length must be > 0
        val dummy = functions.find(_.id == unavailableFunctionConfiguration.id)
        dummy must not be empty
        dummy.get.status.available must equal(false)
      }
    Await.result(all, 10.seconds)
  }

  it should "List multiple saved functions" in {
    val service = application.injector.instanceOf[FunctionService]

    val all = for {
      _ <- service.save(unavailableFunctionConfiguration)
      _ <- service.save(registeredFunction.configuration)
      all <- service.saved()
    } yield all

    all
      .map { functions =>
        functions.length must be >= 2
        val dummy = functions.find(_.id == unavailableFunctionConfiguration.id)
        dummy must not be empty
        dummy.get.status.available must equal(false)

        val available = functions.find(_.id == registeredFunction.configuration.id)
        available must not be empty
        available.get.status.available must equal(true)
      }
    Await.result(all, 10.seconds)
  }

  "The `all` method" should "List all functions, bot available and previously saved" in {
    val service = application.injector.instanceOf[FunctionService]

    val all = for {
      _ <- service.save(dummyFunctionConfiguration)
      all <- service.all(active = false)
    } yield all

    all
      .map { functions =>
        val dummy = functions.find(_.id == dummyFunctionConfiguration.id)
        dummy must not be empty
        dummy.get.status.available must equal(false)

        val available = functions.find(_.id == registeredFunction.configuration.id)
        available must not be empty
        available.get.status.available must equal(true)
      }
    Await.result(all, 10.seconds)
  }

  "The `save` method" should "return the saved function configuration" in {
    val service = application.injector.instanceOf[FunctionService]

    val r = service
      .save(dummyFunctionConfiguration)
      .map { c =>
        c.id must equal(dummyFunctionConfiguration.id)
        c.status.available must equal(false)
      }
    Await.result(r, 10.seconds)
  }

  it should "update function configuration with matching name, keeping configuration paramters as higher priority" in {
    val service = application.injector.instanceOf[FunctionService]

    val saved = for {
      _ <- service.save(dummyFunctionConfiguration)
      c <- service.save(dummyFunctionConfigurationUpdated)
    } yield c

    saved
      .map { c =>
        c.id must equal(dummyFunctionConfiguration.id)
        c.status.enabled must equal(true)
        c.info.headline must equal(dummyFunctionConfiguration.info.headline)
      }
    Await.result(saved, 10.seconds)
  }

  "The `run` method" should "Execute function that is available" in {
    val service     = application.injector.instanceOf[FunctionService]
    val dataService = application.injector.instanceOf[RichDataService]

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

    val executed = for {
      _ <- dataService.saveData(owner.userId, records)
      _ <- service.run(registeredFunction.configuration, None, useAll = false)
      data <- dataService.propertyData(
                Seq(EndpointQuery(s"${registeredFunction.namespace}/${registeredFunction.endpoint}", None, None, None)),
                None,
                orderingDescending = false,
                0,
                None
              )
      functionUpdated <- service.get(registeredFunction.configuration.id)
    } yield {
      data.length must be >= records.length
      data.forall(
        _.endpoint == s"${registeredFunction.namespace}/${registeredFunction.endpoint}"
      ) must equal(true)
      functionUpdated must not be empty
      functionUpdated.get.status.lastExecution must not be empty
    }

    Await.result(executed, 60.seconds)
  }

  it should "Throw an error if no function matching the name is available" in {
    val service = application.injector.instanceOf[FunctionService]
    //service.run(dummyFunctionConfiguration, None, useAll = false) must throwA[RuntimeException].await(1, 30.seconds)
  }

}
