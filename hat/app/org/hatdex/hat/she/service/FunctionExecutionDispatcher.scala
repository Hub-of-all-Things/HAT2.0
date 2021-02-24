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
 * 11 / 2017
 */

package org.hatdex.hat.she.service

import javax.inject.Inject

import scala.concurrent.duration.{ FiniteDuration }
import scala.concurrent.{ ExecutionContext, Future }

import akka.actor.{ Actor, ActorRef, ActorSystem, Props }
import akka.stream.scaladsl.{ Flow, Sink, Source }
import akka.stream.{ ActorMaterializer, OverflowStrategy }
import akka.{ Done, NotUsed }
import org.hatdex.hat.api.service.monitoring.HatDataEventBus
import org.hatdex.hat.api.service.monitoring.HatDataEventBus.DataCreatedEvent
import org.hatdex.hat.resourceManagement.{ HatServerDiscoveryException, HatServerProvider }
import org.hatdex.hat.she.models._
import org.joda.time.DateTime
import play.api.{ Configuration, Logger }

class FunctionTriggerLogger extends Actor {
  private val logger: Logger = Logger(this.getClass)
  def receive: Receive = {
    case (hat: String, configuration: FunctionConfiguration, _: Done) =>
      logger.info(s"Successfully executed function ${configuration.id} for $hat")
  }
}

class FunctionExecutionTriggerHandler @Inject() (
    configuration: Configuration,
    dataEventBus: HatDataEventBus,
    hatServerProvider: HatServerProvider,
    functionService: FunctionService,
    actorSystem: ActorSystem
  )(implicit ec: ExecutionContext) {

  private val logger: Logger                           = Logger(this.getClass)
  implicit private val materializer: ActorMaterializer = ActorMaterializer()(actorSystem)

  protected def findMatchingFunctions(
      hat: String,
      endpoints: Set[String]): Future[Iterable[FunctionConfiguration]] = {
    logger.debug(s"[$hat] Finding matching functions for $endpoints")
    hatServerProvider
      .retrieve(hat)
      .flatMap {
        case Some(hatServer) =>
          functionService
            .all(active = true)(hatServer.db)
            .map(
              _.filter({
                case FunctionConfiguration(_,
                                           _,
                                           _,
                                           FunctionTrigger.TriggerPeriodic(period),
                                           _,
                                           FunctionStatus(true, true, Some(lastExecution), None)
                    ) if lastExecution.isBefore(DateTime.now().minus(period)) =>
                  true
                case FunctionConfiguration(_,
                                           _,
                                           _,
                                           FunctionTrigger.TriggerPeriodic(period),
                                           _,
                                           FunctionStatus(true, true, Some(lastExecution), Some(started))
                    )
                    if lastExecution.isBefore(DateTime.now().minus(period)) && started
                        .isBefore(DateTime.now().minus(functionExecutionTimeout.toMillis)) =>
                  true
                case FunctionConfiguration(_,
                                           _,
                                           _,
                                           FunctionTrigger.TriggerPeriodic(_),
                                           _,
                                           FunctionStatus(true, true, None, None)
                    ) =>
                  true // no execution recoded yet
                case FunctionConfiguration(_,
                                           _,
                                           _,
                                           FunctionTrigger.TriggerPeriodic(_),
                                           _,
                                           FunctionStatus(true, true, None, Some(started))
                    ) if started.isBefore(DateTime.now().minus(functionExecutionTimeout.toMillis)) =>
                  true // no successful execution, current one timed out
                case FunctionConfiguration(_,
                                           _,
                                           _,
                                           FunctionTrigger.TriggerIndividual(),
                                           _,
                                           FunctionStatus(true, true, _, _)
                    ) =>
                  true
                case _ => false // in all other cases, do not trigger
              })
                .filter(
                  _.dataBundle.flatEndpointQueries
                    .map(_.endpoint)
                    .toSet
                    .intersect(endpoints)
                    .nonEmpty
                )
            )

        case None =>
          Future.failed(new HatServerDiscoveryException(s"[$hat] HAT discovery failed during function execution"))
      }
  }

  protected val maxHats: Int      = configuration.get[Int]("she.executionDispatcher.maxHats")
  protected val messageBatch: Int = configuration.get[Int]("she.executionDispatcher.messageBatch")
  protected val messagePeriod: FiniteDuration =
    configuration.get[FiniteDuration]("she.executionDispatcher.messagePeriod")
  protected val matchingFunctionParallelism: Int =
    configuration.get[Int]("she.executionDispatcher.matchingFunctionParallelism")
  protected val functionExecutionParallelism: Int =
    configuration.get[Int]("she.executionDispatcher.functionExecutionParallelism")
  implicit protected val functionExecutionTimeout: FiniteDuration =
    configuration.get[FiniteDuration]("she.executionDispatcher.functionExecutionTimeout")

  protected val functionTriggerLogger: ActorRef = actorSystem.actorOf(Props[FunctionTriggerLogger])

  protected val functionTriggerFlow: Flow[(String, Set[String]), (String, FunctionConfiguration, Done), _] =
    Flow[(String, Set[String])]
      .groupBy[String](maxHats, (event: (String, Set[String])) => event._1)
      .groupedWithin(messageBatch, messagePeriod)
      .map(d => d.reduce((l, r) => l._1 -> (l._2 ++ r._2)))
      .mapAsyncUnordered[Iterable[(String, FunctionConfiguration)]](matchingFunctionParallelism)(d =>
        findMatchingFunctions(d._1, d._2).map(c => c.map((d._1, _)))
      )
      .mapConcat[(String, FunctionConfiguration)](
        _.asInstanceOf[scala.collection.immutable.Iterable[(String, FunctionConfiguration)]]
      )
      .mergeSubstreams
      .mapAsyncUnordered(functionExecutionParallelism) { d =>
        trigger(d._1, d._2)
          .map((d._1, d._2, _))
          .recover({
            case e =>
              logger.error(
                s"[${d._1}] Error when triggering SHE function ${d._2.id} (last execution ${d._2.status.lastExecution}): ${e.getMessage}",
                e
              )
              (d._1, d._2, Done)
          })
      }

  // A flow that chunks information about data coming through into separate substreams to pass through the bounded function trigger flow
  // mitigates th issue with groupBy needing to know maximum number of different keys (K) by ensuring that no more than K items
  // will go through the subflow
  protected val dataEventShaperFlow: Flow[(String, Set[String]), (String, FunctionConfiguration, Done), _] =
    Flow[(String, Set[String])].zipWithIndex
      .splitAfter(i => i._2 % maxHats == 0)
      .map(_._1)
      .via(functionTriggerFlow)
      .mergeSubstreams

  protected val triggerStream: ActorRef = Source
    .actorRef[DataCreatedEvent](bufferSize = 1000, OverflowStrategy.dropNew)
    .collect({
      case DataCreatedEvent(hat, _, _, _, data) =>
        (hat, data.map(_.endpoint).toSet) // only interested in new data coming in
    })
    .via(dataEventShaperFlow)
    .to(Sink.actorRef(functionTriggerLogger, NotUsed))
    .run()

  logger.info("Function Executor Trigger Handler starting")
  dataEventBus.subscribe(triggerStream, classOf[HatDataEventBus.DataCreatedEvent])

  def trigger(
      hat: String,
      conf: FunctionConfiguration,
      useAll: Boolean = false
    )(implicit ec: ExecutionContext): Future[Done] = {
    logger.info(s"[$hat] Triggered function ${conf.id}")
    hatServerProvider
      .retrieve(hat)
      .flatMap {
        _.map { hatServer =>
          functionService
            .run(conf, conf.status.lastExecution, useAll)(hatServer)
            .recover {
              case e => throw SHEFunctionExecutionFailureException(s"$hat function ${conf.id} failed", e)
            }
        } getOrElse {
          Future.failed(
            new HatServerDiscoveryException(
              s"$hat function ${conf.id} HAT $hat discovery failed for function execution"
            )
          )
        }
      }
  }
}
