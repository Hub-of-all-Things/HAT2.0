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
 * 4 / 2018
 */

package org.hatdex.hat.api.service.richData

import java.sql.SQLException
import java.util.UUID
import javax.inject.Inject

import scala.concurrent.Future
import scala.util.Success

import akka.Done
import io.dataswift.models.hat.json.RichDataJsonFormats
import io.dataswift.models.hat._
import org.hatdex.hat.api.service.{ RemoteExecutionContext, UsersService }
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.dal.Tables.{ DataDebit => DbDataDebit, DataDebitPermissions => DbDataDebitPermissions, _ }
import org.hatdex.hat.resourceManagement.HatServer
import org.hatdex.hat.utils.FutureTransformations
import org.hatdex.libs.dal.HATPostgresProfile.api._
import org.joda.time.LocalDateTime
import play.api.Logger
import play.api.libs.json._

class DataDebitService @Inject() (
    usersService: UsersService
  )(implicit val ec: RemoteExecutionContext)
    extends RichDataJsonFormats {

  val logger: Logger = Logger(this.getClass)

  def createDataDebit(
      key: String,
      ddRequest: DataDebitSetupRequest,
      userId: UUID
    )(implicit server: HatServer): Future[DataDebit] = {
    val dataDebitInsert = (DbDataDebit returning DbDataDebit) += DataDebitRow(
            key,
            LocalDateTime.now(),
            ddRequest.requestClientName,
            ddRequest.requestClientUrl,
            ddRequest.requestClientLogoUrl,
            ddRequest.requestApplicationId,
            ddRequest.requestDescription
          )
    val dataDebitBundleInserts = DataBundles ++= Seq(
            Some(
              DataBundlesRow(
                ddRequest.bundle.name,
                Json.toJson(ddRequest.bundle.bundle)
              )
            ),
            ddRequest.conditions.map(b => DataBundlesRow(b.name, Json.toJson(b.bundle)))
          ).flatten

    val dataDebitBundleLinkInserts =
      DbDataDebitPermissions += DataDebitPermissionsRow(
            0,
            key,
            LocalDateTime.now(),
            ddRequest.purpose,
            ddRequest.start.toLocalDateTime,
            ddRequest.period.getStandardSeconds,
            ddRequest.cancelAtPeriodEnd,
            None,
            ddRequest.termsUrl,
            ddRequest.bundle.name,
            ddRequest.conditions.map(_.name),
            accepted = false
          )

    val query = for {
      _ <- dataDebitInsert
      _ <- dataDebitBundleInserts
      _ <- dataDebitBundleLinkInserts
    } yield Done

    server.db
      .run(query.transactionally)
      .flatMap(_ => dataDebit(key)(server.db)) // Retrieve the data debit
      .map(_.get) // Data Debit must be Some as it has been inserted
      .recover {
        case e: SQLException
            if e.getMessage.contains(
              "duplicate key value violates unique constraint \"data_bundles_pkey\""
            ) =>
          println(s"Message: ${e.getMessage()}")
          throw RichDataDuplicateBundleException(
            "Data bundle with such ID already exists"
          )
        case e: SQLException
            if e.getMessage.contains(
              "duplicate key value violates unique constraint \"data_debit_pkey\""
            ) =>
          throw RichDataDuplicateDebitException(
            "Data Debit with such ID already exists"
          )
      }
      .andThen {
        case Success(_) =>
          usersService
            .getUser(userId)
            .flatMap { maybeUser =>
              FutureTransformations.transform(
                maybeUser
                  .map(_.withRoles(DataDebitOwner(key)))
                  .map(usersService.saveUser)
              )
            }
      }
  }

  def updateDataDebitInfo(
      key: String,
      ddRequest: DataDebitSetupRequest
    )(implicit server: HatServer): Future[DataDebit] = {
    val updateQuery = DbDataDebit
      .filter(_.dataDebitKey === key)
      .map(dd =>
        (
          dd.requestClientName,
          dd.requestClientUrl,
          dd.requestClientLogoUrl,
          dd.requestApplicationId,
          dd.requestDescription
        )
      )
      .update(
        (
          ddRequest.requestClientName,
          ddRequest.requestClientUrl,
          ddRequest.requestClientLogoUrl,
          ddRequest.requestApplicationId,
          ddRequest.requestDescription
        )
      )
    server.db
      .run(updateQuery)
      .flatMap(_ => dataDebit(key)(server.db).map(_.get))
  }

  def updateDataDebitPermissions(
      key: String,
      ddRequest: DataDebitSetupRequest,
      userId: UUID
    )(implicit server: HatServer): Future[DataDebit] = {

    val bundleRow = DataBundlesRow(
      ddRequest.bundle.name,
      Json.toJson(ddRequest.bundle.bundle)
    )
    val conditionsRow = ddRequest.conditions.map(c => DataBundlesRow(c.name, Json.toJson(c.bundle)))

    val query = for {
      bundlesWrongOwner <- DbDataDebitPermissions
                             .filter(_.bundleId === bundleRow.bundleId)
                             .filter(_.dataDebitKey =!= key)
                             .length
                             .result
      bundleMatching <- DbDataDebitPermissions
                          .filter(_.bundleId === bundleRow.bundleId)
                          .filter(_.dataDebitKey === key)
                          .length
                          .result
      _ <- (bundlesWrongOwner, bundleMatching) match {
             case (0, 0) =>
               DataBundles += bundleRow // insert a new bundle, fail if previously inserted bundle with same ID
             case (0, n) =>
               DBIO.successful(
                 n
               ) // do nothing if previously linked bundle matches ID
             case (_, _) =>
               DBIO.failed(
                 RichDataDuplicateBundleException(
                   s"Bundle ${bundleRow.bundleId} already linked and could not be reassigned to a different data debit"
                 )
               )
           }
      conditionsWrongOwner <- DbDataDebitPermissions
                                .filter(_.conditions === conditionsRow.map(_.bundleId))
                                .filter(_.dataDebitKey =!= key)
                                .length
                                .result
      conditionsMatching <- DbDataDebitPermissions
                              .filter(_.conditions === conditionsRow.map(_.bundleId))
                              .filter(_.dataDebitKey === key)
                              .length
                              .result
      _ <- (conditionsRow, conditionsWrongOwner, conditionsMatching) match {
             case (None, _, _) => DBIO.successful(0)
             case (Some(conditions), 0, 0) =>
               DataBundles += conditions // insert a new bundle if previously not have a matching bundle
             case (Some(_), 0, n) =>
               DBIO.successful(
                 n
               ) // do nothing if previously linked bundle matches ID
             case (Some(_), _, _) =>
               DBIO.failed(
                 RichDataDuplicateBundleException(
                   s"Condition Bundle ${conditionsRow.map(_.bundleId)} already linked and could not be reassigned to a different data debit"
                 )
               )
           }
      ddb <- (DbDataDebitPermissions returning DbDataDebitPermissions) += DataDebitPermissionsRow(
                   0,
                   key,
                   LocalDateTime.now(),
                   ddRequest.purpose,
                   ddRequest.start.toLocalDateTime,
                   ddRequest.period.getStandardSeconds,
                   ddRequest.cancelAtPeriodEnd,
                   None,
                   ddRequest.termsUrl,
                   ddRequest.bundle.name,
                   ddRequest.conditions.map(_.name),
                   accepted = false
                 ) // Insert a new permissions record
    } yield ddb

    server.db
      .run(query.transactionally)
      .flatMap(_ => dataDebit(key)(server.db)) // Retrieve the data debit
      .map(_.get) // Data Debit must be Some as it has been inserted
      .recover {
        case e: org.postgresql.util.PSQLException
            if e.getMessage.contains(
              "insert or update on table \"data_debit_permissions\" violates foreign key constraint \"data_debit_permissions_data_debit_key_fkey\""
            ) =>
          throw RichDataDebitException(
            "Data Debit being updated does not exist"
          )
      }
      .andThen {
        case Success(_) =>
          usersService
            .getUser(userId)
            .flatMap { maybeUser =>
              FutureTransformations.transform(
                maybeUser
                  .map(_.withRoles(DataDebitOwner(key)))
                  .map(usersService.saveUser)
              )
            }
      }
  }

  def dataDebit(
      dataDebitKey: String
    )(implicit db: Database): Future[Option[DataDebit]] =
    filterDataDebits(
      DbDataDebitPermissions.filter(_.dataDebitKey === dataDebitKey)
    ).map(_.headOption)

  protected def filterDataDebits(
      filter: Query[DbDataDebitPermissions, DataDebitPermissionsRow, Seq]
    )(implicit db: Database): Future[Seq[DataDebit]] = {
    val query = for {
      (ddb, conditions) <- filter.joinLeft(DataBundles).on(_.conditions === _.bundleId)
      dd <- ddb.dataDebitFk
      bundleDefinition <- ddb.dataBundlesFk1
    } yield (dd, (ddb, bundleDefinition, conditions))

    db.run(query.result).map { ddData =>
      ddData
        .groupBy(_._1.dataDebitKey)
        .values
        .map(ddb => ModelTranslation.fromDbModel(ddb.head._1, ddb.unzip._2))
        .toSeq
        .sorted(Ordering.by((_: DataDebit).dateCreated.getEra).reverse)
    }
  }

  def all()(implicit server: HatServer): Future[Seq[DataDebit]] = {
    val legacyWarning =
      "This Data Debit is in a legacy format, and the HAT App is unable to display all the information associated with it fully. This may include a logo, title and full description"
    filterDataDebits(DbDataDebitPermissions)(server.db)
      .map(
        _.map(dd =>
          dd.copy(
            permissions = dd.permissions.map { p =>
              if (p.purpose.isEmpty)
                p.copy(purpose = legacyWarning)
              else
                p
            },
            requestClientName =
              if (dd.requestClientName.isEmpty)
                "Data Exchange"
              else dd.requestClientName,
            requestClientLogoUrl =
              if (dd.requestClientName.isEmpty)
                "https://dex.hubofallthings.com/assets//images/dex.png"
              else dd.requestClientLogoUrl,
            requestClientUrl =
              if (dd.requestClientName.isEmpty)
                "https://dex.hubofallthings.com/"
              else dd.requestClientUrl
          )
        )
      )
  }

  def dataDebitDisable(
      dataDebitKey: String,
      cancelAtPeriodEnd: Boolean
    )(implicit server: HatServer): Future[Done] = {
    val dataBundlesDisabled = DbDataDebitPermissions
      .filter(_.dataDebitKey === dataDebitKey)
      .map(ddp => (ddp.canceledAt, ddp.cancelAtPeriodEnd))
      .update((Some(LocalDateTime.now()), cancelAtPeriodEnd))
    server.db
      .run(dataBundlesDisabled)
      .map(_ => Done)
  }

  def dataDebitEnableNewestPermissions(
      dataDebitKey: String
    )(implicit server: HatServer): Future[Done] = {
    val oldPermissionsDisabled = DbDataDebitPermissions
      .filter(_.dataDebitKey === dataDebitKey)
      .map(_.accepted)
      .update(false)

    val newestPermissions = DbDataDebitPermissions
      .filter(_.dataDebitKey === dataDebitKey)
      .sortBy(_.dateCreated.desc)
      .take(1)

    val permissionsEnabled = DbDataDebitPermissions
      .filter(_.bundleId in newestPermissions.map(_.bundleId))
      .map(dd => (dd.accepted, dd.canceledAt))
      .update((true, None))

    server.db
      .run(DBIO.seq(oldPermissionsDisabled, permissionsEnabled).transactionally)
      .map(_ => Done)
  }

}
