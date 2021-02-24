/*
 * Copyright (C) 2019 HAT Data Exchange Ltd
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
 * Written by Terry Lee <terry.lee@hatdex.org>
 * 2 / 2019
 */

package org.hatdex.hat.api.service

import java.util.UUID
import javax.inject.Inject

import scala.concurrent.Future

import akka.Done
import io.dataswift.models.hat.LogRequest
import play.api.Logger

class LogService @Inject() (implicit val ec: DalExecutionContext) {
  val logger: Logger = Logger(this.getClass)

  def logAction(
      hat: String,
      logDetails: LogRequest,
      applicationDetails: Option[(String, String)]): Future[Done] =
    Future {
      val logId = UUID.randomUUID()
      val applicationVersion =
        applicationDetails.map(a => s"${a._1}@${a._2}").getOrElse("Unknown")
      logger.info(
        s"[${logDetails.logGroup.getOrElse("STATS")}] [$hat] [$logId] [${logDetails.actionCode}] [$applicationVersion] ${logDetails.message
          .getOrElse("")}"
      )

      Done
    }
}
