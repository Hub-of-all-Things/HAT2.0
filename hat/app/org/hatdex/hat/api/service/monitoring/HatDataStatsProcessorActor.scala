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

package org.hatdex.hat.api.service.monitoring

import javax.inject.Inject

import scala.concurrent.{ ExecutionContext, Future }

import akka.Done
import akka.actor.Actor
import io.dataswift.models.hat.{
  DataDebitEvent => DataDebitAction,
  DataDebitOperation,
  DataStats,
  InboundDataStats,
  OutboundDataStats
}
import org.hatdex.hat.api.service.StatsReporter
import org.hatdex.hat.api.service.monitoring.HatDataEventBus.{
  DataCreatedEvent,
  DataDebitEvent,
  RichDataDebitEvent,
  RichDataRetrievedEvent
}
import org.hatdex.hat.resourceManagement.{ HatServer, HatServerDiscoveryException, HatServerProvider }
import play.api.Logger

class HatDataStatsProcessorActor @Inject() (
    processor: HatDataStatsProcessor)
    extends Actor {

  private val log = Logger(this.getClass)

  import HatDataEventBus._

  def receive: Receive = {
    case d: DataCreatedEvent       => processBatchedStats(Seq(d))
    case d: RichDataRetrievedEvent => processBatchedStats(Seq(d))
    case d: RichDataDebitEvent     => processBatchedStats(Seq(d))
    case d: DataDebitEvent         => processBatchedStats(Seq(d))
    case d: Seq[_]                 => processBatchedStats(d)
    case m                         => log.warn(s"Received something else: $m")
  }

  private def processBatchedStats(d: Seq[Any]) = {
    log.debug(s"Process batched stas: $d")
    d.filter(_.isInstanceOf[HatDataEvent])
      .map(_.asInstanceOf[HatDataEvent])
      .groupBy(_.hat)
      .map {
        case (hat, stats) =>
          val aggregated = stats.collect {
            case s: DataCreatedEvent       => processor.computeInboundStats(s)
            case s: RichDataRetrievedEvent => processor.computeOutboundStats(s)
            case e: RichDataDebitEvent     => processor.reportDataDebitEvent(e)
            case e: DataDebitEvent         => processor.reportDataDebitEvent(e)
          }
          hat -> aggregated
      }
      .foreach {
        case (hat, hatStats) =>
          if (hatStats.nonEmpty)
            processor.publishStats(hat, hatStats)
      }
  }

}

class HatDataStatsProcessor @Inject() (
    statsReporter: StatsReporter,
    hatServerProvider: HatServerProvider
  )(implicit
    val ec: ExecutionContext) {

  protected val logger: Logger = Logger(this.getClass)

  def computeInboundStats(event: DataCreatedEvent): InboundDataStats = {
    val endpointStats = JsonStatsService.endpointDataCounts(event.data)
    InboundDataStats(
      event.time.toLocalDateTime,
      event.user,
      endpointStats.toSeq,
      event.logEntry
    )
  }

  def computeOutboundStats(event: RichDataRetrievedEvent): OutboundDataStats = {
    val endpointStats = JsonStatsService.endpointDataCounts(event.data)
    OutboundDataStats(
      event.time.toLocalDateTime,
      event.user,
      event.dataDebit.dataDebitKey,
      endpointStats.toSeq,
      event.logEntry
    )
  }

  def reportDataDebitEvent(event: RichDataDebitEvent): DataDebitAction =
    DataDebitAction(
      event.dataDebit,
      event.operation.toString,
      event.time.toLocalDateTime,
      event.user,
      event.logEntry
    )

  def reportDataDebitEvent(event: DataDebitEvent): DataDebitOperation =
    DataDebitOperation(
      event.dataDebit,
      event.operation.toString,
      event.time.toLocalDateTime,
      event.user,
      event.logEntry
    )

  def publishStats(
      hat: String,
      stats: Iterable[DataStats]): Future[Done] = {
    logger.debug(s"Publish stats for $hat: $stats")

    hatServerProvider.retrieve(hat) flatMap {
      _ map { implicit hatServer: HatServer =>
        statsReporter.reportStatistics(stats.toSeq)
      } getOrElse {
        logger.error(s"No HAT $hat found to report statistics for")
        Future.failed(
          new HatServerDiscoveryException(
            s"HAT $hat discovery failed for stats reporting"
          )
        )
      }
    }
  }
}
