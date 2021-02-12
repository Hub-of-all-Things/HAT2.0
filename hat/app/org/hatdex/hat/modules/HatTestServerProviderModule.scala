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

import akka.actor.ActorSystem
import com.google.inject.{ AbstractModule, Provides }
import net.codingwell.scalaguice.ScalaModule
import org.hatdex.hat.api.service.RemoteExecutionContext
import org.hatdex.hat.api.service.applications.{ TrustedApplicationProvider, TrustedApplicationProviderDex }
import org.hatdex.hat.resourceManagement._
import org.hatdex.hat.resourceManagement.actors.{ HatServerActor, HatServerProviderActor }
import play.api.cache.AsyncCacheApi
import play.api.cache.ehcache.EhCacheComponents
import play.api.inject.ApplicationLifecycle
import play.api.libs.concurrent.AkkaGuiceSupport
import play.api.{ Configuration, Environment }

class HatTestServerProviderModule extends AbstractModule with ScalaModule with AkkaGuiceSupport {

  override def configure(): Unit = {
    bindActor[HatServerProviderActor]("hatServerProviderActor")
    bindActorFactory[HatServerActor, HatServerActor.Factory]

    bind[HatDatabaseProvider].to[HatDatabaseProviderConfig]
    bind[HatKeyProvider].to[HatKeyProviderConfig]
    bind[HatServerProvider].to[HatServerProviderImpl]

    bind[TrustedApplicationProvider].to[TrustedApplicationProviderDex]
    ()
  }

  @Provides @play.cache.NamedCache("hatserver-cache")
  def provideHatServerCache(
      env: Environment,
      config: Configuration,
      lifecycle: ApplicationLifecycle,
      system: ActorSystem
    )(implicit ec: RemoteExecutionContext): AsyncCacheApi = {
    val cacheComponents = new EhCacheComponents {
      def environment: Environment = env
      def configuration: Configuration =
        config.get[Configuration]("hat.serverProvider")
      def applicationLifecycle: ApplicationLifecycle = lifecycle
      def actorSystem: ActorSystem                   = system
      implicit def executionContext                  = ec
    }
    cacheComponents.cacheApi("hatserver-cache", create = true)
  }

}
