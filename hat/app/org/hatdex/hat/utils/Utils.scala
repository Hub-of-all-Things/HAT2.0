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

import scala.collection.immutable.HashMap
import scala.concurrent.{ ExecutionContext, Future }
import scala.util.{ Failure, Success, Try }

import play.api.Logger

object Utils {
  def flatten[T](xs: Seq[Try[T]]): Try[Seq[T]] = {
    val (ss: Seq[Success[T]] @unchecked, fs: Seq[Failure[T]] @unchecked) =
      xs.partition(_.isSuccess)

    if (fs.isEmpty) Success(ss map (_.get))
    else Failure[Seq[T]](fs(0).exception) // Only keep the first failure
  }

  // Utility function to return None for empty sequences
  def seqOption[T](seq: Seq[T]): Option[Seq[T]] =
    if (seq.isEmpty)
      None
    else
      Some(seq)

  def reverseOptionTry[T](a: Option[Try[T]]): Try[Option[T]] =
    a match {
      case None =>
        Success(None)
      case Some(Success(b)) =>
        Success(Some(b))
      case Some(Failure(e)) =>
        Failure(e)
    }

  def mergeMap[A, B](
      ms: Iterable[HashMap[A, B]]
    )(f: (B, B) => B): HashMap[A, B] =
    (for {
      m <- ms
      kv <- m
    } yield kv).foldLeft(HashMap[A, B]()) { (a, kv) =>
      a + (if (a.contains(kv._1)) kv._1 -> f(a(kv._1), kv._2) else kv)
    }

  def time[R](
      name: String,
      logger: Logger
    )(block: => R): R = {
    val t0     = System.nanoTime()
    val result = block // call-by-name
    val t1     = System.nanoTime()
    logger.info(s"[$name] Elapsed time: ${(t1 - t0) / 1000000.0}ms")
    result
  }

  def timeFuture[R](
      name: String,
      logger: Logger
    )(block: => Future[R]
    )(implicit ec: ExecutionContext): Future[R] = {
    val t0 = System.nanoTime()
    block // call-by-name
      .andThen {
        case Success(_) =>
          val t1 = System.nanoTime()
          logger.info(s"[$name] Elapsed time: ${(t1 - t0) / 1000000.0}ms")
      }
  }

}
