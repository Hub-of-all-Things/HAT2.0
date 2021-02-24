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
 * 3 / 2017
 */

package org.hatdex.hat.utils

import javax.inject.Inject

import scala.concurrent.{ ExecutionContext, Future }

import play.api.http.{ HttpErrorHandler, Status }
import play.api.libs.json.{ JsError, Reads }
import play.api.mvc.{ BodyParser, PlayBodyParsers }

class HatBodyParsers @Inject() (
    errorHandler: HttpErrorHandler,
    playBodyParsers: PlayBodyParsers
  )(implicit
    val ec: ExecutionContext) {
  def json[A](implicit reader: Reads[A]): BodyParser[A] =
    BodyParser("json reader") { request =>
      playBodyParsers.json(request) mapFuture {
        case Left(simpleResult) =>
          Future.successful(Left(simpleResult))
        case Right(jsValue) =>
          jsValue.validate(reader) map { a =>
            Future.successful(Right(a))
          } recoverTotal { jsError =>
            val msg = JsError.toJson(jsError).toString()
            errorHandler.onClientError(
              request,
              Status.BAD_REQUEST,
              msg
            ) map Left.apply
          }
      }
    }
}
