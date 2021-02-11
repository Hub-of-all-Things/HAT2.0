package org.hatdex.hat.helpers

import play.api.Configuration
//import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, HatServer }
import scala.concurrent.Future
import org.hatdex.hat.dal.HatDbSchemaMigration
import org.hatdex.libs.dal.HATPostgresProfile.backend.Database
import scala.concurrent.ExecutionContext
import com.dimafeng.testcontainers.{ PostgreSQLContainer }
import org.hatdex.hat.authentication.models.HatUser

trait ContainerUtils {
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

  def databaseReady(
      db: Database,
      c: Configuration
    )(implicit ec: ExecutionContext): Future[Unit] = {
    implicit def hatDatabase: Database = db

    val schemaMigration = new HatDbSchemaMigration(c, hatDatabase, ec)
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
}
