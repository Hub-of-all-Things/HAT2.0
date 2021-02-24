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

package org.hatdex.hat.she.models

import scala.concurrent.Future

import io.dataswift.models.hat.EndpointDataBundle
import org.joda.time.DateTime

trait FunctionExecutable {
  val configuration: FunctionConfiguration
  val namespace: String
  val endpoint: String
  def execute(
      configuration: FunctionConfiguration,
      request: Request): Future[Seq[Response]]
  def bundleFilterByDate(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Future[EndpointDataBundle] = {
    // Explicitly ignore the parameters - compiler complains about unused parameters
    (fromDate, untilDate)
    Future.successful(configuration.dataBundle)
  }
}

class SHEException(
    message: String = "",
    cause: Throwable = None.orNull)
    extends RuntimeException(message, cause)
case class SHEFunctionNotAvailableException(
    message: String = "",
    cause: Throwable = None.orNull)
    extends SHEException(message, cause)
case class SHEFunctionBusyExecutingException(
    message: String = "",
    cause: Throwable = None.orNull)
    extends SHEException(message, cause)
case class SHEFunctionExecutionFailureException(
    message: String = "",
    cause: Throwable = None.orNull)
    extends SHEException(message, cause)
