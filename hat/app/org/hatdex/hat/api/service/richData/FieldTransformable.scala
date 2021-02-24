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

package org.hatdex.hat.api.service.richData

import com.github.tminglei.slickpg.TsVector
import io.dataswift.models.hat._
import org.hatdex.libs.dal.HATPostgresProfile.api._
import org.joda.time.DateTime
import play.api.libs.json._

trait FieldTransformable[In] {
  type Out
  def apply(in: In): Out
}

object FieldTransformable {
  type Aux[I, O] = FieldTransformable[I] { type Out = O }

  import FieldTransformation._

  implicit val generateIdentityTranslation: Aux[Identity, Rep[JsValue] => Rep[JsValue]] =
    new FieldTransformable[Identity] {
      type Out = Rep[JsValue] => Rep[JsValue]

      def apply(in: Identity): Rep[JsValue] => Rep[JsValue] = { value: Rep[JsValue] =>
        value
      }
    }

  implicit val generateDateTimeExtractTranslation: Aux[DateTimeExtract, Rep[JsValue] => Rep[JsValue]] =
    new FieldTransformable[DateTimeExtract] {
      type Out = Rep[JsValue] => Rep[JsValue]

      def apply(in: DateTimeExtract): Rep[JsValue] => Rep[JsValue] = { value =>
        toJson(datePart(in.part, value.asColumnOf[String].asColumnOf[DateTime]))
      }
    }

  implicit val generateTimestampExtractTranslation: Aux[TimestampExtract, Rep[JsValue] => Rep[JsValue]] =
    new FieldTransformable[TimestampExtract] {
      type Out = Rep[JsValue] => Rep[JsValue]

      def apply(in: TimestampExtract): Rep[JsValue] => Rep[JsValue] = { value =>
        toJson(
          datePartTimestamp(
            in.part,
            toTimestamp(value.asColumnOf[String].asColumnOf[Double])
          )
        )
      }
    }

  implicit val generateSearchableTranslation: Aux[Searchable, Rep[JsValue] => Rep[TsVector]] =
    new FieldTransformable[Searchable] {
      type Out = Rep[JsValue] => Rep[TsVector]

      def apply(in: Searchable): Rep[JsValue] => Rep[TsVector] = { value =>
        toTsVector(value.asColumnOf[String])
      }
    }

  def process[I](in: I)(implicit p: FieldTransformable[I]): p.Out = p(in)
}
