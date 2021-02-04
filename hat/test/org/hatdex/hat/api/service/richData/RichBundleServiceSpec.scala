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
// import org.specs2.concurrent.ExecutionEnv
// import org.specs2.mock.Mockito
// import org.specs2.specification.{ BeforeAll, BeforeEach }
import play.api.Logger
import play.api.libs.json.{ JsObject, Json }
//import play.api.test.PlaySpecification
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
import org.hatdex.hat.dal.HatDbSchemaMigration
import java.io.StringReader
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.{ Logger, Application => PlayApplication }

class RichBundleServiceSpec extends AnyFlatSpec with Matchers with RichBundleServiceContext with ForAllTestContainer {

  import scala.concurrent.ExecutionContext.Implicits.global

  override val container = PostgreSQLContainer()
  container.start()

  val hatAddress = "hat.hubofallthings.net"
  val logger     = Logger(this.getClass)

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

  def containerToConfig(c: PostgreSQLContainer): Configuration =
    Configuration.from(
      Map(
        "database" -> (
              Map(
                "dataSourceClass" -> "org.postgresql.ds.PGSimpleDataSource",
                "properties" -> (Map("databaseName" -> c.container.getDatabaseName(),
                                     "user" -> c.username,
                                     "password" -> c.password,
                                     "jdbcUrl" -> c.jdbcUrl
                    )),
                "serverName" -> c.container.getHost(),
                "numThreads" -> 3,
                "connectionPool" -> "disabled",
                "jdbcUrl" -> c.jdbcUrl
              )
            )
      )
    )

  def databaseReady(
      db: Database,
      c: Configuration): Future[Unit] = {
    implicit def hatDatabase: Database = db

    val schemaMigration = new HatDbSchemaMigration(c, hatDatabase, global)
    schemaMigration
      .resetDatabase()
      .flatMap(_ =>
        schemaMigration.run(
          Seq(
            "evolutions/hat-database-schema/11_hat.sql",
            "evolutions/hat-database-schema/12_hatEvolutions.sql",
            "evolutions/hat-database-schema/13_liveEvolutions.sql",
            "evolutions/hat-database-schema/14_newHat.sql"
          )
        )
      )
  }

  def cleanup(hatDatabase: Database): Unit = {
    import org.hatdex.hat.dal.Tables._
    import org.hatdex.libs.dal.HATPostgresProfile.api._

    val endpointRecordsQuery = DataJson.filter(_.source.like("test%")).map(_.recordId)

    val action = DBIO.seq(
      DataDebitBundle.filter(_.bundleId.like("test%")).delete,
      DataDebitContract.filter(_.dataDebitKey.like("test%")).delete,
      DataCombinators.filter(_.combinatorId.like("test%")).delete,
      DataBundles.filter(_.bundleId.like("test%")).delete,
      DataJsonGroupRecords.filter(_.recordId in endpointRecordsQuery).delete,
      DataJsonGroups.filterNot(g => g.groupId in DataJsonGroupRecords.map(_.groupId)).delete,
      DataJson.filter(r => r.recordId in endpointRecordsQuery).delete
    )

    Await.result(hatDatabase.run(action), 60.seconds)
  }

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

  // "The `bundle` method" should "Retrieve a bundle by ID" in {
  //     val service = application.injector.instanceOf[RichBundleService]
  //     val saved = for {
  //       _ <- service.saveBundle(testBundle)
  //       combinator <- service.bundle(testBundle.name)
  //     } yield combinator

  //     saved map { r =>
  //       r must beSome
  //       r.get.name must equalTo(testBundle.name)
  //     } await (3, 10.seconds)
  //   }

  // "The `bundles` method" should "Retrieve a list of bundles" in {
  //     val service = application.injector.instanceOf[RichBundleService]
  //     val saved = for {
  //       _ <- service.saveBundle(testBundle)
  //       _ <- service.saveBundle(testBundle2)
  //       combinator <- service.bundles()
  //     } yield combinator

  //     saved map { r =>
  //       r.length must be greaterThan 1
  //     } await (3, 10.seconds)
  //   }

  // "The `deleteBundle` method" should "Delete bundle by ID" in {
  //     val service = application.injector.instanceOf[RichBundleService]
  //     val saved = for {
  //       _ <- service.saveBundle(testBundle)
  //       _ <- service.saveBundle(testBundle2)
  //       _ <- service.deleteBundle(testBundle.name)
  //       combinators <- service.bundles()
  //     } yield combinators

  //     saved map { r =>
  //       r.find(_.name == testBundle.name) must beNone
  //       r.find(_.name == testBundle2.name) must beSome
  //     } await (3, 10.seconds)
  //   }
  // }
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
}
