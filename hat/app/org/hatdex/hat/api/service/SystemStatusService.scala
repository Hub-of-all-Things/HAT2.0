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

package org.hatdex.hat.api.service

import javax.inject.Inject

import scala.concurrent.Future

import org.hatdex.hat.dal.Tables._
import org.hatdex.libs.dal.HATPostgresProfile.api._
import play.api.Logger

class SystemStatusService @Inject() (implicit val ec: DalExecutionContext) {
  val logger: Logger = Logger(this.getClass)

  def tableSizeTotal(implicit db: Database): Future[Long] = {
    val sizeQuery = DataTableSize.map(_.totalSize).sum
    db.run(sizeQuery.result).map(_.getOrElse(0L))
  }

  def fileStorageTotal(implicit db: Database): Future[Long] = {
    val sizeQuery = HatFile
      .filter(_.status.+>>("status") === "Completed")
      .map(_.status.+>>("size").asColumnOf[Long])
      .sum
    db.run(sizeQuery.result).map(_.getOrElse(0L))
  }
}

object SystemStatusService {
  def humanReadableByteCount(
      bytes: Long,
      si: Boolean = true): (BigDecimal, String) = {
    val unit =
      if (si) 1000
      else 1024
    if (bytes < unit)
      (bytes, "B")
    else {
      val exp = (Math.log(bytes.toDouble) / Math.log(unit.toDouble)).toInt
      val preLetter =
        if (si)
          "kMGTPE"
        else
          "KMGTPE"
      val preSi =
        if (si)
          ""
        else
          "i"
      val pre     = preLetter.substring(exp - 1, exp) + preSi
      val bdbytes = BigDecimal(bytes / Math.pow(unit.toDouble, exp.toDouble))
      (bdbytes, pre + "B")
    }
  }
}
