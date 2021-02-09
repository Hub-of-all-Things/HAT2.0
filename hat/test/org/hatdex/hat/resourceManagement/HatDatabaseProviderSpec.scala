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
 * 1 / 2018
 */

package org.hatdex.hat.resourceManagement

import java.util.UUID

import org.hatdex.hat.resourceManagement.models.{ DatabaseInstance, DatabaseServer, HatKeys, HatSignup }
import org.joda.time.DateTime
import play.api.test.PlaySpecification

import scala.concurrent.duration._

class HatDatabaseProviderSpec extends PlaySpecification with HatServerProviderContext {
  "The `signupDatabaseConfig` method" should {
    "Return a parsed database configuration" in {
      val service = application.injector.instanceOf[HatDatabaseProviderMilliner]
      val signup = HatSignup(
        UUID.randomUUID(),
        "Bob ThePlumber",
        "bobtheplumber",
        "bob@theplumber.com",
        "testing",
        "testing",
        true,
        DateTime.now(),
        Some(DatabaseInstance(UUID.randomUUID(), "testhatdb1", "testing")),
        Some(DatabaseServer(0, "localhost", 5432, DateTime.now(), Seq())),
        Some(HatKeys("", ""))
      )

      val config = service.signupDatabaseConfig(signup)
      config.getLong("idleTimeout") must be equalTo 30.seconds.toMillis
      config.getString("properties.user") must be equalTo "testhatdb1"
      config.getString("properties.databaseName") must be equalTo "testhatdb1"
      config.getString("properties.portNumber") must be equalTo "5432"
    }
  }
}
