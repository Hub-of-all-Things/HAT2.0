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
 * 4 / 2017
 */

package org.hatdex.hat.api.service.monitoring

import io.dataswift.models.hat._
import org.hatdex.hat.api.service.richData.JsonDataTransformer
import org.joda.time.DateTime
import play.api.Logger
import play.api.libs.json.Reads._
import play.api.libs.json.{ JsArray, JsValue, Json, _ }

case class EndpointQueryException(
    message: String = "",
    cause: Throwable = None.orNull)
    extends Exception(message, cause)

object EndpointSubscriberService {
  private val logger = Logger(this.getClass)

  def matchesBundle(
      data: EndpointData,
      bundle: EndpointDataBundle): Boolean = {
    val endpointQueries = bundle.flatEndpointQueries
      .filter(_.endpoint == data.endpoint)

    endpointQueries collectFirst {
      case q if q.filters.isEmpty                             => true
      case q if q.filters.exists(dataMatchesFilters(data, _)) => true
    } getOrElse {
      false
    }
  }

  implicit private val dateReads: Reads[DateTime] =
    JodaReads.jodaDateReads("yyyy-MM-dd'T'HH:mm:ssZ")

  private def dataMatchesFilters(
      data: EndpointData,
      filters: Seq[EndpointQueryFilter]): Boolean = {
    logger.debug("Checking if data matches provided filters")
    filters.exists { f =>
      data.data
        .transform(JsonDataTransformer.parseJsPath(f.field).json.pick)
        .fold(
          invalid = { _ =>
            false
          },
          valid = { fieldData =>
            val data = f.transformation map {
                case _: FieldTransformation.Identity =>
                  fieldData
                case trans: FieldTransformation.DateTimeExtract =>
                  Json.toJson(
                    dateTimeExtractPart(
                      fieldData.as[DateTime](dateReads),
                      trans.part
                    )
                  )
                case trans: FieldTransformation.TimestampExtract =>
                  Json.toJson(
                    dateTimeExtractPart(
                      new DateTime(fieldData.as[Long] * 1000L),
                      trans.part
                    )
                  )
                case trans =>
                  throw EndpointQueryException(
                    s"Invalid field transformation `${trans.getClass.getName}` for ongoing tracking"
                  )
              } getOrElse {
              fieldData
            }
            f.operator match {
              case op: FilterOperator.In       => jsContains(op.value, data)
              case op: FilterOperator.Contains => jsContains(data, op.value)
              case op: FilterOperator.Between =>
                jsLessThanOrEqual(op.lower, data) && jsLessThanOrEqual(
                    data,
                    op.upper
                  )
              case op =>
                throw EndpointQueryException(
                  s"Invalid match operator `${op.getClass.getName}` for ongoing tracking"
                )
            }

          }
        )
    }
  }

  private def dateTimeExtractPart(
      d: DateTime,
      part: String): Int =
    part match {
      case "milliseconds" => d.getMillisOfSecond
      case "second"       => d.getSecondOfMinute
      case "minute"       => d.getMinuteOfDay
      case "hour"         => d.getHourOfDay
      case "day"          => d.getDayOfMonth
      case "week"         => d.getWeekOfWeekyear
      case "month"        => d.getMonthOfYear
      case "year"         => d.getYear
      case "decade"       => d.getYear / 10
      case "century"      => d.getCenturyOfEra
      case "dow"          => d.getDayOfWeek
      case "doy"          => d.getDayOfYear
      case "epoch"        => (d.getMillis / 1000).toInt
    }

  private def jsContains(
      contains: JsValue,
      contained: JsValue): Boolean =
    (contains, contained) match {
      case (a: JsObject, b: JsObject) => b.fieldSet.subsetOf(a.fieldSet)
      case (a: JsArray, b: JsArray)   => a.value.containsSlice(b.value)
      case (a: JsArray, b: JsValue)   => a.value.contains(b)
      case (a: JsValue, b: JsValue)   => a == b
      case _                          => false
    }

  private def jsLessThanOrEqual(
      a: JsValue,
      b: JsValue): Boolean =
    (a, b) match {
      case (aa: JsNumber, bb: JsNumber) => aa.value <= bb.value
      case (aa: JsString, bb: JsString) => aa.value <= bb.value
      case _                            => false
    }
}
