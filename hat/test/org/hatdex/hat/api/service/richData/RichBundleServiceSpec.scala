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

import org.hatdex.hat.api.models._
import play.api.Logger
import play.api.libs.json.{ JsObject, Json }
import org.hatdex.libs.dal.HATPostgresProfile.backend.Database

import org.scalatest._
import matchers.should._
import flatspec._
import com.dimafeng.testcontainers.{ ForAllTestContainer, PostgreSQLContainer }

import scala.concurrent.Await
import scala.concurrent.duration._
import play.api.Configuration
import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, HatServer }
import scala.concurrent.{ Await, Future }
import com.atlassian.jwt.core.keys.KeyUtils
import java.io.StringReader
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.{ Logger, Application => PlayApplication }
import org.hatdex.hat.helpers.{ ContainerUtils }

class RichBundleServiceSpec
    extends AnyFlatSpec
    with Matchers
    with RichBundleServiceContext
    with ContainerUtils
    with ForAllTestContainer {

  import scala.concurrent.ExecutionContext.Implicits.global

  override val container = PostgreSQLContainer()
  container.start()

  val hatAddress            = "hat.hubofallthings.net"
  val logger                = Logger(this.getClass)
  private val configuration = Configuration.from(FakeHatConfiguration.config)
  private val keyUtils      = new KeyUtils()
  private val hatConfig     = configuration.get[Configuration](s"hat.$hatAddress")
  implicit val application: PlayApplication = new GuiceApplicationBuilder()
    .configure(FakeHatConfiguration.config)
    .build()

  implicit val db: Database = Database.forURL(
    url = container.jdbcUrl,
    user = container.username,
    password = container.password
  )

  implicit val hatServer: HatServer = HatServer(
    hatAddress,
    "hat",
    "user@hat.org",
    keyUtils.readRsaPrivateKeyFromPem(new StringReader(hatConfig.get[String]("privateKey"))),
    keyUtils.readRsaPublicKeyFromPem(new StringReader(hatConfig.get[String]("publicKey"))),
    db
  )

  val conf = containerToConfig(container)
  Await.result(databaseReady(db, conf), 60.seconds)

  "The `saveCombinator` method" should "Save a combinator" in {
    val service      = application.injector.instanceOf[RichBundleService]
    val saveOriginal = service.saveCombinator("testCombinator", testEndpointQuery)
    Await.result(saveOriginal, 10.seconds)
  }

  it should "update a combinator" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saveUpdated = for {
      _ <- service.saveCombinator("testCombinator", testEndpointQueryUpdated)
      saved <- service.saveCombinator("testCombinator", testEndpointQueryUpdated)
    } yield saved
    Await.result(saveUpdated, 10.seconds)
  }

  "The `combinator` method" should "Retrieve a combinator" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveCombinator("testCombinator", testEndpointQuery)
      combinator <- service.combinator("testCombinator")
    } yield combinator

    val r = Await.result(saved, 10.seconds)
    r should be('defined)
    r.get.length should equal(2)
  }

  it should "Return None if combinator doesn't exist" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      combinator <- service.combinator("testCombinatornonsense")
    } yield combinator

    val r = Await.result(saved, 10.seconds)
    r should not be 'defined
  }

  "The `combinators` method" should "List all combinators" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveCombinator("testCombinator", testEndpointQuery)
      _ <- service.saveCombinator("testCombinator2", testEndpointQueryUpdated)
      combinators <- service.combinators()
    } yield combinators

    val r = Await.result(saved, 10.seconds)
    r.length should equal(2)
  }

  "The `deleteCombinator` method" should "Delete combinator by ID" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveCombinator("testCombinator", testEndpointQuery)
      _ <- service.saveCombinator("testCombinator2", testEndpointQueryUpdated)
      _ <- service.deleteCombinator("testCombinator")
      combinators <- service.combinators()
    } yield combinators

    val r = Await.result(saved, 10.seconds)
    r.length should equal(1)
    r.head._1 should equal("testCombinator2")
  }

  "The `saveBundle` method" should "Save a bundle" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved   = service.saveBundle(testBundle)
    Await.result(saved, 10.seconds)
  }

  it should "Update a bundle if one already exists" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveBundle(testBundle)
      saved <- service.saveBundle(testBundle)
    } yield saved

    Await.result(saved, 10.seconds)
  }

  "The `bundle` method" should "Retrieve a bundle by ID" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveBundle(testBundle)
      combinator <- service.bundle(testBundle.name)
    } yield combinator

    val r = Await.result(saved, 10.seconds)
    r should be('defined)
    r.get.name should equal(testBundle.name)
  }

  "The `bundles` method" should "Retrieve a list of bundles" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveBundle(testBundle)
      _ <- service.saveBundle(testBundle2)
      combinator <- service.bundles()
    } yield combinator

    val r = Await.result(saved, 10.seconds)
    r.length should be > 1
  }

  "The `deleteBundle` method" should "Delete bundle by ID" in {
    val service = application.injector.instanceOf[RichBundleService]
    val saved = for {
      _ <- service.saveBundle(testBundle)
      _ <- service.saveBundle(testBundle2)
      _ <- service.deleteBundle(testBundle.name)
      combinators <- service.bundles()
    } yield combinators

    val r = Await.result(saved, 10.seconds)
    r.find(_.name == testBundle.name) should not be 'defined
    r.find(_.name == testBundle2.name) should be('defined)
  }
}

trait RichBundleServiceContext {
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

  def testBundleWithRandom(rnd: String): EndpointDataBundle =
    EndpointDataBundle(
      s"testBundle${rnd}",
      Map(
        s"test" -> PropertyQuery(List(EndpointQuery(s"test/test", Some(simpleTransformation), None, None)),
                                 Some("data.newField"),
                                 None,
                                 Some(3)
            ),
        s"complex" -> PropertyQuery(
              List(EndpointQuery(s"test/complex", Some(complexTransformation), None, None)),
              Some("data.newField"),
              None,
              Some(1)
            )
      )
    )

  val testBundle: EndpointDataBundle =
    EndpointDataBundle(
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

  def newConditionsBundle(rnd: String) =
    EndpointDataBundle(
      s"testConditionsBundle${rnd}",
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

  def newConditionsBundle2(rnd: String) =
    EndpointDataBundle(
      s"testConditionsBundle2${rnd}",
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
}
