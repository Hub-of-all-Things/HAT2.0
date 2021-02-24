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
 * 7 / 2018
 */

package org.hatdex.hat.api.service.richData

import javax.inject.Inject

import scala.concurrent.Future

import akka.Done
import akka.actor.ActorSystem
import akka.stream.ActorMaterializer
import akka.stream.scaladsl.{ Flow, Sink, Source }
import org.hatdex.hat.api.service.DalExecutionContext
import org.hatdex.hat.dal.Tables._
import org.hatdex.libs.dal.HATPostgresProfile.api._
import org.joda.time.DateTime
import org.joda.time.format.{ DateTimeFormat, DateTimeFormatter, ISODateTimeFormat }
import play.api.libs.json._

class DataSentintel @Inject() (
    implicit ec: DalExecutionContext,
    actorSystem: ActorSystem) {

  implicit protected val materializer: ActorMaterializer = ActorMaterializer()
  protected val updateBatchSize                          = 500

  //  def validateDataStructure(data: JsValue, configuration: EndpointConfiguration): (JsValue, Option[String], Option[DateTime]) = {
  //    throw new RuntimeException("Not Implemented")
  //  }

  def ensureUniquenessKey(
      source: String,
      key: String
    )(implicit db: Database): Future[Done] = {
    import com.github.tminglei.slickpg.window.PgWindowFuncSupport.WindowFunctions._
    val config = EndpointConfiguration(Some(key), None, None)

    val dbJsonPath = key.split('.').toList

    val clashingRecords = DataJson
      .filter(_.source === source) // only records for this source
      .filterNot(
        _.data.#>>(dbJsonPath) === ""
      ) // and only those that do have the key defined
      .map(r =>
        (
          r.recordId,
          rowNumber().over
            .partitionBy(r.source, r.data #>> dbJsonPath)
            .sortBy(r.date.desc)
        )
      ) // number the rows starting from most recent
      .subquery // subquery used to force generating the query before (incorrectly) Slick tries to use the partition windowing function within where clause
      .filter { case (_, rank) => rank > 1L } // skip the newest row
      .map(_._1) // get record ID for each remaining row

    val deleteQuery = DataJson.filter(_.recordId in clashingRecords).delete

    val updatingStream = Source
      .fromPublisher(
        db.stream(
          DataJson
            .filter(_.source === source)
            .result
            .transactionally
            .withStatementParameters(fetchSize = updateBatchSize)
        )
      )
      .via(Flow[DataJsonRow].grouped(updateBatchSize))
      .mapAsync(1) { batch =>
        db.run(
          DBIO
            .sequence(
              batch
                .map(r =>
                  r.copy(sourceUniqueId = config.getKey(r.data))
                ) // take the value at key as either string or number
                .map(DataJson.insertOrUpdate)
            )
            .transactionally
        ) // update the row with sourceUniqueId inserted
      }

    db.run(deleteQuery)
      .flatMap { _ =>
        updatingStream.runWith(
          Sink.ignore
        ) // the result is not important as long as it succeeds
      }
      .map(_ => Done)
  }

  def updateSourceTimestamp(
      source: String,
      key: String,
      format: String = ""
    )(implicit db: Database): Future[Done] = {
    val config = EndpointConfiguration(None, Some(key), Some(format))

    val updatingStream = Source
      .fromPublisher(
        db.stream(
          DataJson
            .filter(_.source === source)
            .result
            .transactionally
            .withStatementParameters(fetchSize = updateBatchSize)
        )
      )
      .via(Flow[DataJsonRow].grouped(updateBatchSize))
      .mapAsync(parallelism = 1) { batch =>
        db.run(
          DBIO
            .sequence(
              batch
                .map(r => r.copy(sourceTimestamp = config.getTimestamp(r.data))) // take the value at key as DateTime
                .map(DataJson.insertOrUpdate)
            )
            .transactionally
        ) // update the row with sourceUniqueId inserted
      }

    updatingStream
      .runWith(
        Sink.ignore
      ) // the result is not important as long as it succeeds
      .map(_ => Done)
  }
}

case class EndpointConfiguration(
    keyField: Option[String],
    timestampField: Option[String],
    timestampFormat: Option[
      String
    ] // JODA DateTime format or "'epoch'" literal to denote that it is in seconds since epoch, defaults to ISO8601
  ) {
  lazy val keyPath: Option[JsPath] =
    keyField.map(JsonDataTransformer.parseJsPath)
  lazy val timestampPath: Option[JsPath] =
    timestampField.map(JsonDataTransformer.parseJsPath)
  implicit private val timestampJsonFormat: Reads[DateTime] = jodaDateReads(
    timestampFormat.getOrElse("")
  )

  def getKey(d: JsValue): Option[String] =
    keyPath.flatMap(k =>
      k.asSingleJson(d)
        .asOpt[String]
        .orElse(k.asSingleJson(d).asOpt[Long].map(_.toString))
    )

  def getTimestamp(d: JsValue): Option[DateTime] =
    timestampPath.flatMap(_.asSingleJson(d).asOpt[DateTime])

  protected def jodaDateReads(pattern: String): Reads[DateTime] =
    new Reads[DateTime] {

      private val (df, corrector, numberCorrector): (
          DateTimeFormatter,
          String => String,
          Long => Long
      ) =
        pattern match {
          case "" =>
            (
              ISODateTimeFormat.dateOptionalTimeParser,
              identity[String],
              identity[Long]
            )
          case "'epoch'" =>
            (
              ISODateTimeFormat.dateOptionalTimeParser,
              identity[String],
              { x: Long => x * 1000L }
            )
          case _ =>
            (
              DateTimeFormat.forPattern(pattern),
              identity[String],
              identity[Long]
            )
        }

      def reads(json: JsValue): JsResult[DateTime] =
        json match {
          case JsNumber(d) => JsSuccess(new DateTime(numberCorrector(d.toLong)))
          case JsString(s) =>
            parseDate(corrector(s)) match {
              case Some(d) => JsSuccess(d)
              case _ =>
                JsError(
                  Seq(
                    JsPath() -> Seq(
                          JsonValidationError(
                            "error.expected.jodadate.format",
                            pattern
                          )
                        )
                  )
                )
            }
          case _ =>
            JsError(
              Seq(JsPath() -> Seq(JsonValidationError("error.expected.date")))
            )
        }

      private def parseDate(input: String): Option[DateTime] =
        scala.util.control.Exception
          .nonFatalCatch[DateTime] opt (DateTime.parse(input, df))
    }
}
