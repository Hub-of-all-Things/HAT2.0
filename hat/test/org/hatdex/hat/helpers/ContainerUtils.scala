package org.hatdex.hat.helpers

import scala.concurrent.Await
import scala.concurrent.duration._
import play.api.Configuration
import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, HatServer }
import scala.concurrent.{ Await, Future }
import org.hatdex.hat.dal.HatDbSchemaMigration
import org.hatdex.libs.dal.HATPostgresProfile.backend.Database
import scala.concurrent.ExecutionContext
import com.dimafeng.testcontainers.{ PostgreSQLContainer }

trait ContainerUtils {
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
