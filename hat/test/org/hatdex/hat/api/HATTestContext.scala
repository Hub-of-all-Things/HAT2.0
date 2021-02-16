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

package org.hatdex.hat.api

import java.io.StringReader
import java.util.UUID

import akka.Done
import akka.stream.Materializer
import com.amazonaws.services.s3.AmazonS3
import com.atlassian.jwt.core.keys.KeyUtils
import com.google.inject.name.Named
import com.google.inject.{ AbstractModule, Provides }
import com.mohiva.play.silhouette.api.{ Environment, Silhouette, SilhouetteProvider }
import com.mohiva.play.silhouette.test._
import net.codingwell.scalaguice.ScalaModule
import org.hatdex.hat.FakeCache
import org.hatdex.hat.api.models.{ DataCredit, DataDebitOwner, Owner }
import org.hatdex.hat.api.service._
import org.hatdex.hat.api.service.applications.{ TestApplicationProvider, TrustedApplicationProvider }
import org.hatdex.hat.authentication.HatApiAuthEnvironment
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.dal.HatDbSchemaMigration
import org.hatdex.hat.phata.models.MailTokenUser
import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, FakeHatServerProvider, HatServer, HatServerProvider }
import org.hatdex.hat.utils.{ ErrorHandler, HatMailer, LoggingProvider, MockLoggingProvider }
import org.hatdex.libs.dal.HATPostgresProfile.backend.Database
// import org.specs2.mock.Mockito
// import org.specs2.specification.Scope
import play.api.cache.AsyncCacheApi
import play.api.http.HttpErrorHandler
import play.api.i18n.{ Lang, Messages, MessagesApi }
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.{ Application, Configuration, Logger }
import play.cache.NamedCacheImpl

import scala.concurrent.duration._
import scala.concurrent.{ Await, Future }
import java.sql.Connection

trait HATTestContext { //extends Scope with Mockito {
  import scala.concurrent.ExecutionContext.Implicits.global
  // Initialize configuration
  val hatAddress            = "hat.hubofallthings.net"
  val hatUrl                = s"http://$hatAddress"
  private val configuration = Configuration.from(FakeHatConfiguration.config)
  private val hatConfig     = configuration.get[Configuration](s"hat.$hatAddress")

  // Build up the FakeEnvironment for authentication testing
  private val keyUtils = new KeyUtils()
  implicit protected def hatDatabase: Database =
    Database.forConfig("", hatConfig.get[Configuration]("database").underlying)
  implicit val hatServer: HatServer = HatServer(
    hatAddress,
    "hat",
    "user@hat.org",
    keyUtils.readRsaPrivateKeyFromPem(new StringReader(hatConfig.get[String]("privateKey"))),
    keyUtils.readRsaPublicKeyFromPem(new StringReader(hatConfig.get[String]("publicKey"))),
    hatDatabase
  )

  // Setup default users for testing
  val owner = HatUser(UUID.randomUUID(),
                      "hatuser",
                      Some("$2a$06$QprGa33XAF7w8BjlnKYb3OfWNZOuTdzqKeEsF7BZUfbiTNemUW/n."),
                      "hatuser",
                      Seq(Owner()),
                      enabled = true
  )
  val dataDebitUser = HatUser(
    UUID.randomUUID(),
    "dataDebitUser",
    Some("$2a$06$QprGa33XAF7w8BjlnKYb3OfWNZOuTdzqKeEsF7BZUfbiTNemUW/n."),
    "dataDebitUser",
    Seq(DataDebitOwner("")),
    enabled = true
  )
  val dataCreditUser = HatUser(
    UUID.randomUUID(),
    "dataCreditUser",
    Some("$2a$06$QprGa33XAF7w8BjlnKYb3OfWNZOuTdzqKeEsF7BZUfbiTNemUW/n."),
    "dataCreditUser",
    Seq(DataCredit(""), DataCredit("namespace")),
    enabled = true
  )
  implicit val environment: Environment[HatApiAuthEnvironment] = FakeEnvironment[HatApiAuthEnvironment](
    Seq(owner.loginInfo -> owner, dataDebitUser.loginInfo -> dataDebitUser, dataCreditUser.loginInfo -> dataCreditUser),
    hatServer
  )

  // Helpers to (re-)initialize the test database and await for it to be ready
  val devHatMigrations = Seq(
    "evolutions/hat-database-schema/11_hat.sql",
    "evolutions/hat-database-schema/12_hatEvolutions.sql",
    "evolutions/hat-database-schema/13_liveEvolutions.sql",
    "evolutions/hat-database-schema/14_newHat.sql"
  )

  def databaseReady: Future[Unit] = {
    val schemaMigration = new HatDbSchemaMigration(configuration, hatDatabase, global)
    schemaMigration
      .resetDatabase()
      .flatMap(_ => schemaMigration.run(devHatMigrations))
      .flatMap { _ =>
        val usersService = application.injector.instanceOf[UsersService]
        for {
          _ <- usersService.saveUser(dataCreditUser)
          _ <- usersService.saveUser(dataDebitUser)
          _ <- usersService.saveUser(owner)
        } yield ()
      }
  }

  def databaseReady(db: Database): Future[Unit] = {
    def hatDatabase: Database = db
    implicit val hatServer: HatServer = HatServer(
      hatAddress,
      "hat",
      "user@hat.org",
      keyUtils.readRsaPrivateKeyFromPem(new StringReader(hatConfig.get[String]("privateKey"))),
      keyUtils.readRsaPublicKeyFromPem(new StringReader(hatConfig.get[String]("publicKey"))),
      hatDatabase
    )

    val schemaMigration = new HatDbSchemaMigration(configuration, hatDatabase, global)
    schemaMigration
      .resetDatabase()
      .flatMap(_ => schemaMigration.run(devHatMigrations))
      .flatMap { _ =>
        val usersService = application.injector.instanceOf[UsersService]
        for {
          _ <- usersService.saveUser(dataCreditUser)
          _ <- usersService.saveUser(dataDebitUser)
          _ <- usersService.saveUser(owner)
        } yield ()
      }
  }

  // val mockMailer: HatMailer = mock[HatMailer]
  // doReturn(Done).when(mockMailer).passwordReset(any[String], any[String])(any[MessagesApi], any[Lang], any[HatServer])

  val fileManagerS3Mock = FileManagerS3Mock()

  //val mockLogger = mock[Logger]

  lazy val remoteEC = new RemoteExecutionContext(application.actorSystem)

  /**
    * A fake Guice module.
    */
  class FakeModule extends AbstractModule with ScalaModule {
    override def configure(): Unit = {
      bind[Environment[HatApiAuthEnvironment]].toInstance(environment)
      bind[Silhouette[HatApiAuthEnvironment]].to[SilhouetteProvider[HatApiAuthEnvironment]]
      bind[HatServerProvider].toInstance(new FakeHatServerProvider(hatServer))
      bind[FileManager].to[FileManagerS3]
      bind[MailTokenService[MailTokenUser]].to[MailTokenUserService]
      //bind[HatMailer].toInstance(mockMailer)
      bind[HttpErrorHandler].to[ErrorHandler]
      bind[AsyncCacheApi].annotatedWith(new NamedCacheImpl("user-cache")).to[FakeCache]
      bind[AsyncCacheApi].to[FakeCache]
      //bind[LoggingProvider].toInstance(new MockLoggingProvider(mockLogger))
    }

    @Provides
    def provideCookieAuthenticatorService(): AwsS3Configuration =
      fileManagerS3Mock.s3Configuration

    @Provides @Named("s3client-file-manager")
    def provides3Client(): AmazonS3 =
      fileManagerS3Mock.mockS3client

  }

  class ExtrasModule extends AbstractModule with ScalaModule {
    override def configure(): Unit =
      bind[TrustedApplicationProvider].toInstance(new TestApplicationProvider(Seq()))
  }

  lazy val application: Application = new GuiceApplicationBuilder()
    .configure(FakeHatConfiguration.config)
    .overrides(new FakeModule)
    .overrides(new ExtrasModule)
    .build()

  implicit lazy val materializer: Materializer = application.materializer

  def before(): Unit =
    Await.result(databaseReady, 60.seconds)
}
