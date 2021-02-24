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

package org.hatdex.hat.dal

import scala.concurrent.ExecutionContext

import com.typesafe.config.Config
import org.hatdex.libs.dal.BaseSchemaMigrationImpl
import play.api.{ Configuration, Logger }
import slick.driver.JdbcProfile

class HatDbSchemaMigration(
    config: Configuration,
    val db: JdbcProfile#Backend#Database,
    implicit val ec: ExecutionContext)
    extends BaseSchemaMigrationImpl {
  protected val configuration: Config    = config.underlying
  protected val logger: org.slf4j.Logger = Logger(this.getClass).logger
}
