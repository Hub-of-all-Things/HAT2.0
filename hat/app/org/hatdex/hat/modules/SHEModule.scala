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

package org.hatdex.hat.modules

import scala.collection.JavaConverters._
import scala.concurrent.duration._
import scala.concurrent.{ Await, ExecutionContext, Future }

import com.google.inject.{ AbstractModule, Provides }
import com.typesafe.config.Config
import net.codingwell.scalaguice.ScalaModule
import io.dataswift.models.hat.applications.Version
import org.hatdex.hat.she.models.LambdaFunctionLoader
import org.hatdex.hat.she.service.{ FunctionExecutableRegistry, FunctionExecutionTriggerHandler }
import org.hatdex.hat.utils.FutureTransformations
import play.api.libs.concurrent.AkkaGuiceSupport
import play.api.{ ConfigLoader, Configuration, Logger }

class SHEModule extends AbstractModule with ScalaModule with AkkaGuiceSupport {
  val logger: Logger = Logger(this.getClass)

  override def configure(): Unit = {
    bind[FunctionExecutionTriggerHandler].asEagerSingleton()
    ()
  }

  implicit val seqFunctionConfigLoader: ConfigLoader[Seq[FunctionConfig]] =
    new ConfigLoader[Seq[FunctionConfig]] {
      def load(
          config: Config,
          path: String): Seq[FunctionConfig] = {
        val configs = config.getConfigList(path).asScala
        logger.info(s"Got SHE function configs: $configs")
        configs.map { config =>
          FunctionConfig(
            config.getString("id"),
            Version(config.getString("version")),
            config.getString("baseUrl"),
            config.getString("namespace"),
            config.getString("endpoint"),
            config.getBoolean("experimental")
          )
        }
      }
    }

  @Provides
  def provideFunctionExecutableRegistry(
      config: Configuration,
      loader: LambdaFunctionLoader
    )(implicit ec: ExecutionContext): FunctionExecutableRegistry = {

    val includeExperimental: Boolean =
      config.getOptional[Boolean]("she.beta").getOrElse(false)

    val eventuallyFunctionsLoaded = Future.sequence(
      config
        .get[Seq[FunctionConfig]]("she.functions")
        .filter(c => !c.experimental || (includeExperimental && c.experimental))
        .map(c =>
          FutureTransformations.futureToFutureTry(
            loader.load(c.id, c.version, c.baseUrl, c.namespace, c.endpoint)
          )
        )
    )

    val functionsLoaded = Await.result(eventuallyFunctionsLoaded, 30.seconds)

    // ignore any functions that failed to load without stopping the whole application
    new FunctionExecutableRegistry(
      functionsLoaded.filter(_.isSuccess).flatMap(_.toOption)
    )
  }

  case class FunctionConfig(
      id: String,
      version: Version,
      baseUrl: String,
      namespace: String,
      endpoint: String,
      experimental: Boolean)
}
