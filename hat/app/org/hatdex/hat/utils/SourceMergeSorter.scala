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
 * 3 / 2018
 */

package org.hatdex.hat.utils

import scala.annotation.tailrec

import akka.NotUsed
import akka.stream.scaladsl.{ GraphDSL, MergeSorted, Source }
import akka.stream.stage.GraphStage
import akka.stream.{ FanInShape2, SourceShape }

class SourceMergeSorter {
  def mergeWithSorter[A](
      originSources: Seq[Source[A, NotUsed]]
    )(implicit ordering: Ordering[A]): Source[A, NotUsed] =
    merge(originSources, sorter[A])

  private def merge[A](
      originSources: Seq[Source[A, NotUsed]],
      f: (Source[A, NotUsed], Source[A, NotUsed]) => Source[A, NotUsed]): Source[A, NotUsed] =
    originSources match {
      case Nil =>
        Source.empty[A]

      case sources =>
        @tailrec
        def reducePairs(sources: Seq[Source[A, NotUsed]]): Source[A, NotUsed] =
          sources match {
            case Seq(s) =>
              s

            case _ =>
              reducePairs(
                sources
                  .grouped(2)
                  .map {
                    case Seq(a)    => a
                    case Seq(a, b) => f(a, b)
                  }
                  .toSeq
              )
          }

        reducePairs(sources)
    }

  private def sorter[A](
      s1: Source[A, NotUsed],
      s2: Source[A, NotUsed]
    )(implicit ord: Ordering[A]): Source[A, NotUsed] =
    combineSources(new MergeSorted[A], s1, s2)((_, _) => NotUsed)

  private def combineSources[A, MatIn0, MatIn1, Mat](
      combinator: GraphStage[FanInShape2[A, A, A]],
      s0: Source[A, MatIn0],
      s1: Source[A, MatIn1]
    )(combineMat: (MatIn0, MatIn1) => Mat): Source[A, Mat] =
    Source.fromGraph(GraphDSL.create(s0, s1)(combineMat) { implicit builder => (s0, s1) =>
      import GraphDSL.Implicits._
      val merge = builder.add(combinator)
      s0 ~> merge.in0
      s1 ~> merge.in1
      SourceShape(merge.out)
    })
}
