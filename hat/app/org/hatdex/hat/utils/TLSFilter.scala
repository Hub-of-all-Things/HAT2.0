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
 * 5 / 2018
 */

package org.hatdex.hat.utils

import javax.inject.Inject

import scala.concurrent.{ ExecutionContext, Future }

import akka.stream.Materializer
import play.api.Environment
import play.api.mvc._

class TLSFilter @Inject() (
    implicit
    val mat: Materializer,
    ec: ExecutionContext,
    env: Environment)
    extends Filter {
  def apply(
      nextFilter: RequestHeader => Future[Result]
    )(requestHeader: RequestHeader): Future[Result] =
    if (
      requestHeader.headers
        .get("X-Forwarded-Proto")
        .getOrElse("http") != "https" && env.mode == play.api.Mode.Prod
    )
      if (requestHeader.method == "GET")
        Future.successful(
          Results.MovedPermanently(
            "https://" + requestHeader.host + requestHeader.uri
          )
        )
      else
        Future.successful(
          Results.BadRequest("This service requires strict transport security")
        )
    else
      nextFilter(requestHeader).map(
        _.withHeaders("Strict-Transport-Security" -> "max-age=31536000")
      )
}
