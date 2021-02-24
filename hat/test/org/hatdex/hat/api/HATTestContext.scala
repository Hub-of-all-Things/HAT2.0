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

import scala.concurrent.duration._
import scala.concurrent.{ Await, Future }

import akka.Done
import akka.stream.Materializer
import com.amazonaws.services.s3.AmazonS3
import com.atlassian.jwt.core.keys.KeyUtils
import com.dimafeng.testcontainers.{ PostgreSQLContainer }
import com.google.inject.name.Named
import com.google.inject.{ AbstractModule, Provides }
import com.mohiva.play.silhouette.api.{ Environment, Silhouette, SilhouetteProvider }
import com.mohiva.play.silhouette.test._
import net.codingwell.scalaguice.ScalaModule
import org.hatdex.hat.FakeCache
import io.dataswift.models.hat.{ DataCredit, DataDebitOwner, Owner }
import org.hatdex.hat.api.service._
import org.hatdex.hat.api.service.applications.{ TestApplicationProvider, TrustedApplicationProvider }
import org.hatdex.hat.authentication.HatApiAuthEnvironment
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.dal.HatDbSchemaMigration
import org.hatdex.hat.phata.models.MailTokenUser
import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, FakeHatServerProvider, HatServer, HatServerProvider }
import org.hatdex.hat.utils.{ ErrorHandler, HatMailer, LoggingProvider, MockLoggingProvider }
import org.hatdex.libs.dal.HATPostgresProfile.backend.Database
import org.mockito.ArgumentMatchers.{ any }
import org.mockito.Mockito._
import org.scalatestplus.mockito.MockitoSugar
import play.api.cache.AsyncCacheApi
import play.api.http.HttpErrorHandler
import play.api.i18n.{ Lang, MessagesApi }
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.{Application, Configuration}
import play.cache.NamedCacheImpl

trait HATTestContext extends MockitoSugar {
  import scala.concurrent.ExecutionContext.Implicits.global

  val container = PostgreSQLContainer()
  container.start()
  val conf = containerToConfig(container)

  def containerToConfig(c: PostgreSQLContainer): Configuration =
    Configuration.from(
      Map(
        "play.cache.createBoundCaches" -> "false",
        "resourceManagement.hatDBIdleTimeout" -> "30 seconds",
        "hat" -> Map(
              "hat.hubofallthings.net" -> Map(
                    "ownerEmail" -> "user@hat.org",
                    "database" -> (
                          Map(
                            "dataSourceClass" -> "org.postgresql.ds.PGSimpleDataSource",
                            "properties" -> (Map("databaseName" -> c.container.getDatabaseName(),
                                                 "user" -> c.username,
                                                 "password" -> c.password,
                                                 "url" -> c.jdbcUrl
                                )),
                            "serverName" -> c.container.getHost(),
                            "numThreads" -> 10,
                            "connectionPool" -> "disabled"
                          )
                        ),
                    "publicKey" -> """-----BEGIN PUBLIC KEY-----
          |MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAznT9VIjovMEB/hoZ9j+j
          |z9G+WWAsfj9IB7mAMQEICoLMWHC1ZnO4nrqTrRiQFKKrWekjhXFRp8jQZmGhv/sw
          |h5EsIcbRUzNNPSBmiCM0NXHG8wwN8cFigHXLQB0p4ekOWOHpEXfIZkTN5VlpUq1o
          |PdbgMXRW8NdU+Mwr7qQiUnHxaW0imFiahPs3n5Q3KLt2nWcxlvazeaRDphkEtFTk
          |JCaFx9TPzd1NSYpBidSMC2cwhVM6utaNk3ZRktCs+y0iFezL606x28P6+VuDkb19
          |6OxWEvSSxL3+1KQbKi3B9Hg/BNhigGsqQ35GzVPVygT7m90u9nNlxJ7KvfQDQc8t
          |dQIDAQAB
          |-----END PUBLIC KEY-----""".stripMargin,
                    "privateKey" -> """-----BEGIN RSA PRIVATE KEY-----
          |MIIEowIBAAKCAQEAznT9VIjovMEB/hoZ9j+jz9G+WWAsfj9IB7mAMQEICoLMWHC1
          |ZnO4nrqTrRiQFKKrWekjhXFRp8jQZmGhv/swh5EsIcbRUzNNPSBmiCM0NXHG8wwN
          |8cFigHXLQB0p4ekOWOHpEXfIZkTN5VlpUq1oPdbgMXRW8NdU+Mwr7qQiUnHxaW0i
          |mFiahPs3n5Q3KLt2nWcxlvazeaRDphkEtFTkJCaFx9TPzd1NSYpBidSMC2cwhVM6
          |utaNk3ZRktCs+y0iFezL606x28P6+VuDkb196OxWEvSSxL3+1KQbKi3B9Hg/BNhi
          |gGsqQ35GzVPVygT7m90u9nNlxJ7KvfQDQc8tdQIDAQABAoIBAF00Voub1UolbjNb
          |cD4Jw/fVrjPmJaAHDIskNRmqaAlqvDrvAw3SD1ZlT7b04FLYjzfjdvxOyLjRATg/
          |OkkT6vhA0yYafjSr8+I1JuSt0+uOxmzCE+eA0OnCg/QZVmedEbORpWkT5P46cKNq
          |RpCjJWzJfWQGLBvFcqBxeCHfqnkCFESRDG+YTUTzQ3Z4tdvXh/Wn7ZNAsJFaM2+x
          |krJF7bBas9MJ/A8fumtuickr6DpFB6/nQsKqou3wDsMPN9SeTgXAzvufnssK0bGx
          |8Z0F7pQUsl7CF2VuSXH2rcmW59JOpqPeZQ1JfrJZRxZ839vY+0BUF+Ti3FVJBb95
          |aXLqHF8CgYEA+vwJCI6y+W/Cfwu79ssoJB+038sJftqkpKcFCipTsvX26h8o5+Vd
          |BSvo58cjbXSV6a7PevkQvlgpKPki9SZnE+LoEmq1KbmN6yV0kev4Kzmi7P9Lz1Z8
          |XRkt5KWQSMn65ZhLRHeomM71TgzDye1QI6rIKp4oumZUrlj8xGPB7VMCgYEA0pUq
          |DSprxCQajw5WiH9X2sswrzDuK/+YAPZFBcRkK2KS9KGkltqlU9EmfZSX794vqfZw
          |WBzJMRvxy0tF9QYSFahGivk98dzUUfARx79lIrKDBRVeUuP5LQ762K7BhDanym5a
          |4YvzRPsJGHUT6Kyn1nsoP/CXqr1fxbv/HaN7WRcCgYEAz+x+O1WklZptobyB4kmZ
          |npuZx5C39ByEK1emiC5amrbD8F8SD1LnhgJDd8h05Beini5Q+opdwaLdrnD+8eL3
          |n/Tp12AJZ2CuXrDv6nd3Z6/e9sHk9waqDqJub65tYq/Zp91L9ZO/26AQfrF6fc2Z
          |B4NTQmM2UH24B5v3A2e1X7sCgYBXnFuMcrO3PNYX4n05+NESZCrzGEZe483XyJ3a
          |0mRicHZ3dLDHWlwiTQfYg3PbBfOKoM8IuaEy309vpveKA2aOwB3pP9z3vUpQdLLR
          |Cd4H24ELImLF1bcbefn/IGW+ngac/+CrqdAiSNb15+/Kg9qoL0EFqRFQpc0stRRk
          |vllZLQKBgEuos9IFTnXvF5+NpwQJ54t4YQW/StgPL7sPVA86irXnuT3VwdVNg2VF
          |AZa/LU3jAXt2iTziR0LTKueamj/V+YM4qVyc/LhUPvjKlsCjyLBb647p3C/ogYbj
          |mO9kGhALaD5okBcI/VuAQiFvBXdK0ii/nVcBApXEu47PG4oYUgPI
          |-----END RSA PRIVATE KEY-----""".stripMargin
                  )
            )
      )
    )

  // Initialize configuration
  val hatAddress            = "hat.hubofallthings.net"
  val hatUrl                = s"http://$hatAddress"
  private val configuration = conf //Configuration.from(FakeHatConfiguration.config)
  private val hatConfig     = configuration.get[Configuration](s"hat.$hatAddress")

  implicit val db: Database = Database.forURL(
    url = container.jdbcUrl,
    user = container.username,
    password = container.password
  )

  // Build up the FakeEnvironment for authentication testing
  private val keyUtils = new KeyUtils()
  implicit val hatServer: HatServer = HatServer(
    hatAddress,
    "hat",
    "user@hat.org",
    keyUtils.readRsaPrivateKeyFromPem(new StringReader(hatConfig.get[String]("privateKey"))),
    keyUtils.readRsaPublicKeyFromPem(new StringReader(hatConfig.get[String]("publicKey"))),
    db
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
    val schemaMigration = new HatDbSchemaMigration(configuration, db, global)
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

  val mockLogger            = mock[play.api.Logger]
  val mockMailer: HatMailer = mock[HatMailer]
  when(mockMailer.passwordReset(any[String], any[String])(any[MessagesApi], any[Lang], any[HatServer])).thenReturn(Done)

  val fileManagerS3Mock = FileManagerS3Mock()

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
      bind[HatMailer].toInstance(mockMailer)
      bind[HttpErrorHandler].to[ErrorHandler]
      bind[AsyncCacheApi].annotatedWith(new NamedCacheImpl("user-cache")).to[FakeCache]
      bind[AsyncCacheApi].to[FakeCache]
      bind[LoggingProvider].toInstance(new MockLoggingProvider(mockLogger))
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

  // override protected def beforeAll(): Unit = ()
  // override protected def afterAll(): Unit  = container.close()
}
