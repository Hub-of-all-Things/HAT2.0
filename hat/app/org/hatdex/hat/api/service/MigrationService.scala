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
 * 8 / 2017
 */

package org.hatdex.hat.api.service

import java.util.UUID
import javax.inject.Inject

import scala.concurrent.Future

import akka.NotUsed
import akka.stream.Materializer
import akka.stream.scaladsl.{ Flow, Keep, RunnableGraph, Sink, Source }
import com.mohiva.play.silhouette.api.actions.SecuredRequest
import io.dataswift.models.hat.json.HatJsonFormats
import io.dataswift.models.hat.{ ApiDataRecord, _ }
import org.hatdex.hat.api.service.monitoring.HatDataEventDispatcher
import org.hatdex.hat.api.service.richData.RichDataService
import org.hatdex.hat.authentication.HatApiAuthEnvironment
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.dal.Tables._
import org.hatdex.libs.dal.HATPostgresProfile.api._
import org.joda.time.LocalDateTime
import play.api.Logger
import play.api.libs.json._

class MigrationService @Inject() (
    richDataService: RichDataService,
    dataEventDispatcher: HatDataEventDispatcher
  )(implicit
    materializer: Materializer,
    ec: DalExecutionContext) {

  protected val logger: Logger = Logger(this.getClass)

  protected def convertRecordJson(
      record: ApiDataRecord,
      includeTimestamp: Boolean,
      liftDataItem: Option[String]): JsResult[JsObject] = {
    implicit val localDateTimeWrites =
      HatJsonFormats.DefaultJodaLocalDateTimeWrites

    val dataPath = liftDataItem map { liftItem =>
      __ \ 'data \ liftItem
    } getOrElse {
      __ \ 'data
    }

    val transformation =
      if (includeTimestamp)
        dataPath.json.pick(
          __.json.update(
            (__ \ 'lastUpdated).json
              .put(Json.toJson(record.lastUpdated.getOrElse(LocalDateTime.now())))
          )
        )
      else
        dataPath.json.pick[JsObject]

    HatJsonFormats
      .flattenRecordValues(record)
      .transform(transformation)
  }

  def migrateOldDataRecord(
      userId: UUID,
      record: ApiDataRecord
    )(implicit db: Database,
      request: SecuredRequest[HatApiAuthEnvironment, _]): Future[Int] =
    record.tables.map { tables =>
      val savedRecords = tables.map { table =>
        convertRecordJson(
          record,
          includeTimestamp = true,
          Some(table.name)
        ) map { data =>
          richDataService
            .saveData(
              userId,
              Seq(
                EndpointData(
                  s"${table.source}/${table.name}",
                  None,
                  None,
                  None,
                  data,
                  None
                )
              )
            )
            .andThen(
              dataEventDispatcher.dispatchEventDataCreated(
                s"migrated record for ${table.source}/${table.name}"
              )
            )
            .map(_ => 1)
        } getOrElse Future.successful(0)
      }

      Future.sequence(savedRecords).map(_.sum)
    } getOrElse {
      Future.successful(0)
    }

  def migrateOldData(
      userId: UUID,
      endpoint: String,
      fromTableName: String,
      fromSource: String,
      updatedSince: Option[LocalDateTime],
      updatedUntil: Option[LocalDateTime],
      includeTimestamp: Boolean
    )(implicit db: Database,
      request: SecuredRequest[HatApiAuthEnvironment, _]): Future[Long] = {
    val parallelMigrations = 10

    val eventualCount: Future[Long] = db.run {
      // Get the legacy table ID
      DataTable
        .filter(t => t.sourceName === fromSource && t.name === fromTableName && t.deleted === false)
        .result
    } map { tables =>
      tables.map(ModelTranslation.fromDbModel(_, None, None))
    } map (_.head.id.get) flatMap { tableId =>
      val migratedCountSource =
        getTableValuesStreaming(tableId, updatedSince, updatedUntil) map { record =>
          convertRecordJson(record, includeTimestamp, Some(fromTableName))
        } via {
          Flow[JsResult[JsObject]].filter(
            _.isSuccess
          ) // Filter out unsuccessfully extracted data objects
        } via {
          Flow[JsResult[JsObject]].map(_.get) // Unwrap Json Objects
        } via Flow[JsObject].mapAsync(parallelMigrations) { oldJson =>
              richDataService
                .saveData(
                  userId,
                  Seq(EndpointData(endpoint, None, None, None, oldJson, None))
                )
                .andThen(
                  dataEventDispatcher.dispatchEventDataCreated(
                    s"migrated data to $endpoint"
                  )
                )
                .map(_ => 1L)
                .recover {
                  case e =>
                    logger.debug(
                      s"Error while migrating data record: ${e.getMessage}"
                    )
                    0L
                }
            }

      val sink = Sink.fold[Long, Long](0)(_ + _)
      val runnable: RunnableGraph[Future[Long]] =
        migratedCountSource.toMat(sink)(Keep.right)
      runnable.run()
    }

    eventualCount
  }

  def getTableValuesStreaming(
      tableId: Int,
      updatedSince: Option[LocalDateTime] = None,
      updatedUntil: Option[LocalDateTime] = None
    )(implicit db: Database): Source[ApiDataRecord, NotUsed] = {
    // Get All Data Table trees matching source and name
    val dataTableTreesQuery = for {
      rootTable <- DataTableTree.filter(_.id === tableId)
      tree <- DataTableTree.filter(t => t.rootTable === rootTable.id && t.deleted === false)
    } yield tree

    val eventualTables =
      DataService.buildDataTreeStructures(dataTableTreesQuery, Set(tableId))

    val fieldsetQuery = dataTableTreesQuery
      .join(DataField)
      .on(_.id === _.tableIdFk)
      .map(_._2) // Only fields
      .filter(_.deleted === false) // That have not been deleted
      .distinct // And are distinct

    val valuesQuery = fieldsetQuery
      .join(DataValue)
      .on(_.id === _.fieldId)
      .map(_._2)
      .filter(v => v.deleted === false)
      .filter(v => updatedSince.fold(true.bind)(v.lastUpdated >= _))
      .filter(v => updatedUntil.fold(true.bind)(v.lastUpdated <= _))

    val recordsQuery = DataRecord
      .filter(
        _.id in valuesQuery.sortBy(_.recordId.desc).map(_.recordId).distinct
      )
      .filter(r => r.deleted === false)
      .sortBy(_.lastUpdated.asc)

    val valueQuery = for {
      record <- recordsQuery
      value <- valuesQuery.filter(_.recordId === record.id)
      field <- value.dataFieldFk if field.deleted === false
    } yield (record, field, value)

    val result = db.stream(
      valueQuery.result.transactionally
        .withStatementParameters(fetchSize = 1000)
    )

    val dataStream: Source[ApiDataRecord, NotUsed] = Source
      .fromPublisher(result)
      .groupBy(10000, _._1.id)
      .map(Seq(_))
      .reduce[Seq[(DataRecordRow, DataFieldRow, DataValueRow)]]((l, r) => l.++(r))
      .mergeSubstreams
      .mapAsync(10) { data =>
        eventualTables.map(tables => DataService.restructureTableValuesToRecords(data, tables).head)
      }

    dataStream
  }
}
