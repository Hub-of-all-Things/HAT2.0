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

package org.hatdex.hat.authentication.models

import java.util.UUID

import com.mohiva.play.silhouette.api.{ Identity, LoginInfo }
import io.dataswift.models.hat._
import org.hatdex.hat.resourceManagement.HatServer

case class HatUser(
    userId: UUID,
    email: String,
    pass: Option[String],
    name: String,
    roles: Seq[UserRole],
    enabled: Boolean)
    extends Identity {
  def loginInfo(implicit hatServer: HatServer): LoginInfo =
    LoginInfo(hatServer.domain, email)

  def withRoles(roles: UserRole*): HatUser =
    this.copy(roles = (this.roles.toSet ++ roles.toSet).toSeq)

  def withoutRoles(roles: UserRole*): HatUser =
    this.copy(roles = (this.roles.toSet -- roles.toSet).toSeq)

  lazy val primaryRole: UserRole = {
    if (roles.contains(Owner()))
      Owner()
    else if (roles.contains(Platform()))
      Platform()
    else if (roles.contains(DataCredit("")))
      DataCredit("")
    else if (roles.contains(DataDebitOwner("")))
      DataDebitOwner("")
    else
      Validate()
  }
}
