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
 * Written by Marios Tsekis <marios.tsekis@hatdex.org>
 * 2 / 2019
 */
package org.hatdex.hat.she.mappers

import java.util.UUID

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

import io.dataswift.models.hat.{ EndpointData, PropertyQuery }
import org.hatdex.hat.api.service.richData.RichDataService
import org.hatdex.hat.resourceManagement.HatServer
import org.hatdex.hat.she.models.StaticDataValues
import play.api.Logger
import play.api.libs.json._

trait StaticDataEndpointMapper extends JodaWrites with JodaReads {
  protected lazy val logger: Logger = Logger(this.getClass)

  def dataQueries(): Seq[PropertyQuery]
  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      endpoint: String): Seq[StaticDataValues]

  final def staticDataRecords(
    )(implicit
      hatServer: HatServer,
      richDataService: RichDataService): Future[Seq[StaticDataValues]] = {

    val staticData = Future.sequence(dataQueries.map { query =>
      val eventualDataSource: Future[Seq[EndpointData]] =
        richDataService.propertyData(
          query.endpoints,
          query.orderBy,
          orderingDescending = query.ordering.contains("descending"),
          skip = 0,
          limit = query.limit,
          createdAfter = None
        )(hatServer.db)

      eventualDataSource.map { dataSource =>
        dataSource
          .map(item => mapDataRecord(item.recordId.get, item.data, item.endpoint))
          .headOption
          .getOrElse(Seq())
      }
    })

    staticData.map(_.flatten)
  }
}
