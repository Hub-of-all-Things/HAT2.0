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

import javax.inject.{ Inject, Named }

import scala.concurrent.duration._

import akka.actor.{ ActorRef, ActorSystem }
import akka.stream.scaladsl.{ Sink, Source }
import akka.stream.{ ActorMaterializer, OverflowStrategy }
import akka.{ Done, NotUsed }

trait HatDataEventRouter {
  def init(): Done
}

class HatDataEventRouterImpl @Inject() (
    dataEventBus: HatDataEventBus,
    @Named("hatDataStatsProcessor") statsProcessor: ActorRef,
    implicit val actorSystem: ActorSystem)
    extends HatDataEventRouter {

  implicit private val materializer: ActorMaterializer = ActorMaterializer()

  init()

  def init(): Done = {
    // Inbound/outbound data stats are reported via a buffering stage to control load and network traffic
    dataEventBus.subscribe(
      buffer(statsProcessor),
      classOf[HatDataEventBus.DataCreatedEvent]
    )
    dataEventBus.subscribe(
      buffer(statsProcessor),
      classOf[HatDataEventBus.RichDataRetrievedEvent]
    )
    // Data Debit Events are dispatched without buffering
    dataEventBus.subscribe(
      statsProcessor,
      classOf[HatDataEventBus.RichDataDebitEvent]
    )
    dataEventBus.subscribe(
      statsProcessor,
      classOf[HatDataEventBus.DataDebitEvent]
    )
    Done
  }

  /**
    * Uses Akka streams to generate a proxy actor that buffers messages up to a certain batch size and time, whichever
    * gets reached first
    *
    * @param target Actor for which messages should be buffered
    * @param batch batch size
    * @param period time limit for every batch to be collected
    * @returns ActorRef of a new actor to send messages to
    */
  private def buffer(
      target: ActorRef,
      batch: Int = 100,
      period: FiniteDuration = 60.seconds): ActorRef =
    Source
      .actorRef(bufferSize = 1000, OverflowStrategy.dropNew)
      .groupedWithin(batch, period)
      .to(Sink.actorRef(target, NotUsed))
      .run()

}
