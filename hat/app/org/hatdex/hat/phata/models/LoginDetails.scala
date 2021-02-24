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

package org.hatdex.hat.phata.models

import scala.collection.JavaConverters._

import me.gosimple.nbvcxz._
import play.api.libs.functional.syntax._
import play.api.libs.json.{ JsError, _ }

case class ApiPasswordChange(
    newPassword: String,
    password: Option[String])

object ApiPasswordChange {

  private val nbvcxzDictionaryList =
    resources.ConfigurationBuilder.getDefaultDictionaries

  private val nbvcxzConfiguration = new resources.ConfigurationBuilder()
    .setMinimumEntropy(40d)
    .setDictionaries(nbvcxzDictionaryList)
    .createConfiguration()

  private val nbvcxz = new Nbvcxz(nbvcxzConfiguration)

  private def passwordGuessesToScore(guesses: BigDecimal) = {
    val DELTA = 5
    if (guesses < 1e3 + DELTA)
      0
    else if (guesses < 1e6 + DELTA)
      1
    else if (guesses < 1e8 + DELTA)
      2
    else if (guesses < 1e10 + DELTA)
      3
    else
      4
  }

  def passwordStrength(implicit reads: Reads[String]): Reads[String] =
    Reads[String] { js =>
      reads
        .reads(js)
        .flatMap { a =>
          val estimate = nbvcxz.estimate(a)
          if (passwordGuessesToScore(estimate.getGuesses) >= 2)
            JsSuccess(a)
          else
            JsError(
              JsonValidationError(
                "Minimum password requirement strength not met",
                estimate.getFeedback.getSuggestion.asScala.toList: _*
              )
            )
        }
    }

  implicit val passwordChangeApiReads: Reads[ApiPasswordChange] =
    ((JsPath \ "newPassword").read[String](passwordStrength) and
        (JsPath \ "password").readNullable[String])(ApiPasswordChange.apply _)
  implicit val passwordChangeApiWrites: Writes[ApiPasswordChange] =
    Json.format[ApiPasswordChange]
}

case class ApiPasswordResetRequest(
    email: String)

object ApiPasswordResetRequest {
  implicit val passwordResetApiReads: Reads[ApiPasswordResetRequest] =
    (__ \ 'email).read[String](Reads.email).map { email =>
      ApiPasswordResetRequest(email)
    }
  implicit val passwordResetApiWrites: Writes[ApiPasswordResetRequest] =
    Json.format[ApiPasswordResetRequest]
}
case class ApiValidationRequest(
    email: String,
    applicationId: String)

object ApiValidationRequest {
  implicit val passwordValidationApiReads: Reads[ApiValidationRequest] =
    ((JsPath \ "email").read[String](Reads.email) and
        (JsPath \ "applicationId").read[String])(ApiValidationRequest.apply _)

  implicit val passwordValidationApiWrites: Writes[ApiValidationRequest] =
    Json.format[ApiValidationRequest]
}
