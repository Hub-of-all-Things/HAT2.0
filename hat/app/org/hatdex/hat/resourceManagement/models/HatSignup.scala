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

package org.hatdex.hat.resourceManagement.models

import java.util.UUID

import org.joda.time.DateTime
import play.api.libs.json.{ Json, OFormat }

case class DatabaseInstance(
    id: UUID,
    name: String,
    password: String)

case class DatabaseServer(
    id: Int,
    host: String,
    port: Int,
    dateCreated: DateTime,
    databases: Seq[DatabaseInstance])

case class HatKeys(
    privateKey: String,
    publicKey: String)

case class HatSignup(
    id: UUID,
    fullName: String,
    username: String,
    email: String,
    pass: String,
    dbPass: String,
    created: Boolean,
    registerTime: DateTime,
    database: Option[DatabaseInstance],
    databaseServer: Option[DatabaseServer],
    keys: Option[HatKeys])

object HatSignup {
  import play.api.libs.json.JodaWrites._
  import play.api.libs.json.JodaReads._

  implicit val databaseInstanceFormat: OFormat[DatabaseInstance] = Json.format[DatabaseInstance]
  implicit val databaseServerFormat: OFormat[DatabaseServer]     = Json.format[DatabaseServer]
  implicit val hatKeysFormat: OFormat[HatKeys]                   = Json.format[HatKeys]
  implicit val hatSignupFormat: OFormat[HatSignup]               = Json.format[HatSignup]
}
