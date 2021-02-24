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

import javax.inject.Inject

import scala.concurrent.Future

import io.dataswift.models.hat.json.RichDataJsonFormats
import io.dataswift.models.hat._
import org.hatdex.hat.api.service.DalExecutionContext
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.dal.Tables._
import org.hatdex.libs.dal.HATPostgresProfile.api._
import play.api.Logger
import play.api.libs.json._

class RichBundleService @Inject() (implicit ec: DalExecutionContext) extends RichDataJsonFormats {

  val logger: Logger = Logger(this.getClass)

  def saveCombinator(
      combinatorId: String,
      combinator: Seq[EndpointQuery]
    )(implicit db: Database): Future[Unit] = {
    val insertQuery = DataCombinators.insertOrUpdate(
      DataCombinatorsRow(combinatorId, Json.toJson(combinator))
    )
    db.run(insertQuery).map(_ => ())
  }

  def combinator(
      combinatorId: String
    )(implicit db: Database): Future[Option[Seq[EndpointQuery]]] =
    db.run(DataCombinators.filter(_.combinatorId === combinatorId).result) map { queries =>
      queries.headOption map { q =>
        q.combinator.as[Seq[EndpointQuery]]
      }
    }

  def combinators(
    )(implicit db: Database): Future[Seq[(String, Seq[EndpointQuery])]] =
    db.run(DataCombinators.result) map { queries =>
      queries map { q =>
        (q.combinatorId, q.combinator.as[Seq[EndpointQuery]])
      }
    }

  def deleteCombinator(
      combinatorId: String
    )(implicit db: Database): Future[Unit] = {
    val deleteQuery =
      DataCombinators.filter(_.combinatorId === combinatorId).delete
    db.run(deleteQuery).map(_ => ())
  }

  def saveBundle(
      bundle: EndpointDataBundle
    )(implicit db: Database): Future[Unit] = {
    val insertQuery = DataBundles.insertOrUpdate(
      DataBundlesRow(bundle.name, Json.toJson(bundle.bundle))
    )
    db.run(insertQuery).map(_ => ())
  }

  def bundle(
      bundleId: String
    )(implicit db: Database): Future[Option[EndpointDataBundle]] =
    db.run(DataBundles.filter(_.bundleId === bundleId).result)
      .map(_.headOption.map(ModelTranslation.fromDbModel))

  def bundles()(implicit db: Database): Future[Seq[EndpointDataBundle]] =
    db.run(DataBundles.result)
      .map(_.map(ModelTranslation.fromDbModel))

  def deleteBundle(bundleId: String)(implicit db: Database): Future[Unit] = {
    val deleteQuery = DataBundles.filter(_.bundleId === bundleId).delete
    db.run(deleteQuery).map(_ => ())
  }
}
