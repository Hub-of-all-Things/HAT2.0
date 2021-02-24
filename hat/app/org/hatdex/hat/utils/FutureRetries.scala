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

package org.hatdex.hat.utils

import scala.concurrent.duration._
import scala.concurrent.{ ExecutionContext, Future }
import scala.util.Random

import akka.actor.Scheduler
import akka.pattern.after

object FutureRetries {
  def retry[T](
      f: => Future[T],
      delays: List[FiniteDuration]
    )(implicit ec: ExecutionContext,
      s: Scheduler): Future[T] =
    f recoverWith {
        case _ if delays.nonEmpty => after(delays.head, s)(retry(f, delays.tail))
      }

  def withDefault(
      delays: List[FiniteDuration],
      retries: Int,
      default: FiniteDuration): List[FiniteDuration] =
    if (delays.length > retries)
      delays take retries
    else
      delays ++ List.fill(retries - delays.length)(default)

  def withJitter(
      delays: List[FiniteDuration],
      maxJitter: Double,
      minJitter: Double): List[FiniteDuration] =
    delays.map { delay =>
      val jitter =
        delay * (minJitter + (maxJitter - minJitter) * Random.nextDouble)
      jitter match {
        case d: FiniteDuration => d
        case _                 => delay
      }
    }

  val fibonacci: Stream[FiniteDuration] =
    0.seconds #:: 1.seconds #:: (fibonacci zip fibonacci.tail).map { t =>
          t._1 + t._2
        }
}
