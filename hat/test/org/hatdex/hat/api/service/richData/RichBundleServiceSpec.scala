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

import scala.concurrent.Await
import scala.concurrent.duration._

import io.dataswift.test.common.BaseSpec
import org.hatdex.hat.api.HATTestContext
import io.dataswift.models.hat._
import org.scalatest.{ BeforeAndAfterAll, BeforeAndAfterEach }
import play.api.Logger
import play.api.libs.json.{ JsObject, Json }

class RichBundleServiceSpec
    extends BaseSpec
    with BeforeAndAfterEach
    with BeforeAndAfterAll
    with RichBundleServiceContext {

  import scala.concurrent.ExecutionContext.Implicits.global
  val logger = Logger(this.getClass)

  override def beforeAll: Unit =
    Await.result(databaseReady, 60.seconds)

  override def afterAll() =
    container.stop()

  override def beforeEach: Unit = {
    import org.hatdex.hat.dal.Tables._
    import org.hatdex.libs.dal.HATPostgresProfile.api._

    val endpointRecrodsQuery = DataJson.filter(_.source.like("test%")).map(_.recordId)

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

  "The `saveCombinator` method" should "Save a combinator" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved   = service.saveCombinator("testCombinator", testEndpointQuery)
    saved map { _ =>
      true must equal(true)
    }
    Await.result(saved, 10.seconds)
  }

  it should "Update a combinator if one already exists" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveCombinator("testCombinator", testEndpointQueryUpdated)
      saved <- service.saveCombinator("testCombinator", testEndpointQueryUpdated)
    } yield saved

    saved map { _ =>
      true must equal(true)
    }
    Await.result(saved, 10.seconds)
  }

  "The `combinator` method" should "Retrieve a combinator" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveCombinator("testCombinator", testEndpointQuery)
      combinator <- service.combinator("testCombinator")
    } yield combinator

    saved map { r =>
      r must equal(Some)
      r.get.length must equal(2)
    }
    Await.result(saved, 10.seconds)
  }

  it should "Return None if combinator doesn't exist" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      combinator <- service.combinator("testCombinator")
    } yield combinator

    saved map { r =>
      r must equal(None)
    }
    Await.result(saved, 10.seconds)
  }

  "The `combinators` method" should "List all combinators" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveCombinator("testCombinator", testEndpointQuery)
      _ <- service.saveCombinator("testCombinator2", testEndpointQueryUpdated)
      combinators <- service.combinators()
    } yield combinators

    saved map { r =>
      r.length must equal(2)
    }
    Await.result(saved, 10.seconds)
  }

  "The `deleteCombinator` method" should "Delete combinator by ID" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveCombinator("testCombinator", testEndpointQuery)
      _ <- service.saveCombinator("testCombinator2", testEndpointQueryUpdated)
      _ <- service.deleteCombinator("testCombinator")
      combinators <- service.combinators()
    } yield combinators

    saved map { r =>
      r.length must equal(1)
      r.head._1 must equal("testCombinator2")
    }
    Await.result(saved, 10.seconds)
  }

  "The `saveBundle` method" should "Save a bundle" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved   = service.saveBundle(testBundle)
    saved map { _ =>
      true must equal(true)
    }
    Await.result(saved, 10.seconds)
  }

  it should "Update a bundle if one already exists" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveBundle(testBundle)
      saved <- service.saveBundle(testBundle)
    } yield saved

    saved map { _ =>
      true must equal(true)
    }
    Await.result(saved, 10.seconds)
  }

  "The `bundle` method" should "Retrieve a bundle by ID" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveBundle(testBundle)
      combinator <- service.bundle(testBundle.name)
    } yield combinator

    saved map { r =>
      r must equal(Some)
      r.get.name must equal(testBundle.name)
    }
    Await.result(saved, 10.seconds)
  }

  "The `bundles` method" should "Retrieve a list of bundles" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveBundle(testBundle)
      _ <- service.saveBundle(testBundle2)
      combinator <- service.bundles()
    } yield combinator

    saved map { r =>
      r.length must be > 1
    }
    Await.result(saved, 10.seconds)
  }

  "The `deleteBundle` method" should "Delete bundle by ID" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveBundle(testBundle)
      _ <- service.saveBundle(testBundle2)
      _ <- service.deleteBundle(testBundle.name)
      combinators <- service.bundles()
    } yield combinators

    saved map { r =>
      r.find(_.name == testBundle.name) must equal(None)
      r.find(_.name == testBundle2.name) must equal(Some)
    }
    Await.result(saved, 10.seconds)
  }

}

trait RichBundleServiceContext extends HATTestContext {
  protected val simpleTransformation: JsObject = Json
    .parse("""
      | {
      |   "data.newField": "anotherField",
      |   "data.arrayField": "object.objectFieldArray",
      |   "data.onemore": "object.education[1]"
      | }
    """.stripMargin)
    .as[JsObject]

  protected val complexTransformation: JsObject = Json
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

  val testBundleA = EndpointDataBundle(
    "testBundleA",
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

  val testBundleB = EndpointDataBundle(
    "testBundleB",
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

  val conditionsBundle = EndpointDataBundle(
    "testConditionsBundle",
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

  val conditionsBundle2 = EndpointDataBundle(
    "testConditionsBundle2",
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

  val conditionsBundleA = EndpointDataBundle(
    "testConditionsBundleA",
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

  val conditionsBundleB = EndpointDataBundle(
    "testConditionsBundleB",
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
}
