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

package org.hatdex.hat.modules

import java.util.UUID
import javax.inject.Inject

import com.typesafe.config.Config
import net.codingwell.scalaguice.ScalaModule
import org.hatdex.hat.api.models.{ Owner, Platform }
import org.hatdex.hat.api.service.{ DalExecutionContext, UsersService }
import org.hatdex.hat.authentication.models.HatUser
import org.hatdex.hat.dal.SchemaMigration
import org.hatdex.libs.dal.HATPostgresProfile.api.Database
import play.api.libs.concurrent.AkkaGuiceSupport
import play.api.{ ConfigLoader, Configuration, Logger }

import scala.concurrent.Future

class DevHatInitializationModule extends ScalaModule with AkkaGuiceSupport {

  /**
   * Configures the module.
   */
  def configure() = {
    bind[DevHatInitializer].asEagerSingleton()
  }
}

class DevHatInitializer @Inject() (
    configuration: Configuration,
    schemaMigration: SchemaMigration,
    usersService: UsersService) extends DalExecutionContext {
  val logger = Logger(this.getClass)

  import DevHatConfig.configLoader

  val devHats = configuration.get[Map[String, DevHatConfig]]("devhats")
  val devHatMigrations = configuration.get[Seq[String]]("devhatMigrations")

  logger.info(s"Initializing HATs: $devHats")
  devHats.values.map(initializeHat)

  def initializeHat(hat: DevHatConfig) = {
    implicit val database = Database.forConfig("", hat.database)

    val eventuallyMigrated = for {
      _ <- schemaMigration.run(devHatMigrations)
      _ <- setupCredentials(hat)
    } yield ()

    eventuallyMigrated map {
      case _ =>
        logger.info(s"Database successfully initialized for ${hat.owner}")
    } recover {
      case e =>
        logger.error(s"Database initialisation failed for ${hat.owner}: ${e.getMessage}", e)
    } map {
      case _ =>
        logger.debug(s"Shutting down connection to database for ${hat.owner}")
        database.shutdown
    }
  }

  def setupCredentials(hat: DevHatConfig)(implicit database: Database): Future[Unit] = {
    logger.debug(s"Setup credentials for ${hat.owner}")
    val ownerId = UUID.fromString("694dd8ed-56ae-4910-abf1-6ec4887b4c42")
    val platformId = UUID.fromString("6507ae16-13d7-479b-8ebc-65c28fec1634")
    for {
      savedOwner <- usersService.saveUser(HatUser(ownerId, hat.owner, Some(hat.ownerPasswordHash), hat.ownerName, Seq(Owner()), enabled = true))
      savedPlatform <- usersService.saveUser(HatUser(platformId, hat.platform, Some(hat.platformPasswordHash), hat.platformName, Seq(Platform()), enabled = true))
    } yield {
      logger.info(s"Saved owner: $savedOwner")
      logger.info(s"Saved platform: $savedPlatform")
      ()
    }
  }
}

case class DevHatConfig(
    owner: String,
    ownerName: String,
    ownerPasswordHash: String,
    platform: String,
    platformName: String,
    platformPasswordHash: String,
    database: Config)

object DevHatConfig {
  implicit val configLoader: ConfigLoader[DevHatConfig] = new ConfigLoader[DevHatConfig] {
    def load(rootConfig: Config, path: String): DevHatConfig = {
      val config = ConfigLoader.configurationLoader.load(rootConfig, path)
      DevHatConfig(
        owner = config.get[String]("owner"),
        ownerName = config.get[String]("ownerName"),
        ownerPasswordHash = config.get[String]("ownerPasswordHash"),
        platform = config.get[String]("platform"),
        platformName = config.get[String]("platformName"),
        platformPasswordHash = config.get[String]("platformPasswordHash"),
        database = config.get[Config]("database"))
    }
  }
}
