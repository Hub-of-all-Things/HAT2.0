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

package org.hatdex.hat.dal

import scala.annotation.tailrec

import io.dataswift.models.hat.json.HatJsonFormats
import io.dataswift.models.hat.{
  DataDebit => ApiDataDebit,
  DataDebitPermissions => ApiDataDebitPermissions,
  UserRole => ApiUserRole,
  _
}
import org.hatdex.hat.authentication.models.{ HatAccessLog, HatUser }
import org.hatdex.hat.dal.Tables._
import org.hatdex.hat.phata.models.MailTokenUser
import org.joda.time.Duration

object ModelTranslation {
  def fromDbModel(user: UserUserRow): HatUser =
    HatUser(user.userId, user.email, user.pass, user.name, Seq(), user.enabled)

  def fromDbModel(userInfo: (UserUserRow, Seq[UserRoleRow])): HatUser = {
    val roles =
      userInfo._2.map(r => ApiUserRole.userRoleDeserialize(r.role, r.extra))
    val user = userInfo._1
    HatUser(user.userId, user.email, user.pass, user.name, roles, user.enabled)
  }

  def fromInternalModel(user: HatUser): User =
    User(
      user.userId,
      user.email,
      user.pass,
      user.name,
      user.primaryRole.title.toLowerCase(),
      user.roles
    )
  def fromExternalModel(
      user: User,
      enabled: Boolean): HatUser =
    HatUser(user.userId, user.email, user.pass, user.name, user.roles, enabled)
      .withRoles(ApiUserRole.userRoleDeserialize(user.role, None))

  def fromDbModel(field: DataFieldRow): ApiDataField =
    ApiDataField(
      Some(field.id),
      Some(field.dateCreated),
      Some(field.lastUpdated),
      Some(field.tableIdFk),
      field.name,
      None
    )

  def fromDbModel(
      record: DataRecordRow,
      tables: Option[Seq[ApiDataTable]]): ApiDataRecord =
    new ApiDataRecord(
      Some(record.id),
      Some(record.dateCreated),
      Some(record.lastUpdated),
      record.name,
      tables
    )

  def fromDbModel(
      table: DataTableRow,
      fields: Option[Seq[ApiDataField]],
      subTables: Option[Seq[ApiDataTable]]): ApiDataTable =
    new ApiDataTable(
      Some(table.id),
      Some(table.dateCreated),
      Some(table.lastUpdated),
      table.name,
      table.sourceName,
      fields,
      subTables
    )

  def fromDbModel(
      table: DataTableTreeRow,
      fields: Option[Seq[ApiDataField]],
      subTables: Option[Seq[ApiDataTable]]): ApiDataTable =
    new ApiDataTable(
      table.id,
      table.dateCreated,
      table.lastUpdated,
      table.name.getOrElse(""),
      table.sourceName.getOrElse(""),
      fields,
      subTables
    )

  def fromDbModel(value: DataValueRow): ApiDataValue =
    ApiDataValue(
      Some(value.id),
      Some(value.dateCreated),
      Some(value.lastUpdated),
      value.value,
      None,
      None
    )

  def fromDbModel(value: DataStatsLogRow): DataStats = {
    import io.dataswift.models.hat.json.DataStatsFormat.dataStatsFormat
    value.stats.as[DataStats]
  }

  def fromDbModel(
      userMailTokensRow: UserMailTokensRow): MailTokenUser =
    MailTokenUser(
      userMailTokensRow.id,
      userMailTokensRow.email,
      userMailTokensRow.expirationTime.toDateTime,
      userMailTokensRow.isSignup
    )

  def fromDbModel(hatFileRow: HatFileRow): ApiHatFile = {
    import HatJsonFormats.apiHatFileStatusFormat
    ApiHatFile(
      Some(hatFileRow.id),
      hatFileRow.name,
      hatFileRow.source,
      Some(hatFileRow.dateCreated.toDateTime),
      Some(hatFileRow.lastUpdated.toDateTime),
      hatFileRow.tags,
      hatFileRow.title,
      hatFileRow.description,
      hatFileRow.sourceUrl,
      Some(hatFileRow.status.as[HatFileStatus.Status]),
      None,
      None,
      Some(hatFileRow.contentPublic),
      None
    )
  }

  def fromDbModel(hatFileAccessRow: HatFileAccessRow): ApiHatFilePermissions =
    ApiHatFilePermissions(hatFileAccessRow.userId, hatFileAccessRow.content)

  def fromDbModel(
      userAccessLogRow: UserAccessLogRow,
      user: HatUser): HatAccessLog =
    HatAccessLog(
      userAccessLogRow.date.toDateTime,
      user,
      userAccessLogRow.`type`,
      userAccessLogRow.scope,
      userAccessLogRow.applicationName,
      userAccessLogRow.applicationResource
    )

  def fromDbModel(dataJsonRow: DataJsonRow): EndpointData =
    EndpointData(
      dataJsonRow.source,
      Some(dataJsonRow.recordId),
      dataJsonRow.sourceTimestamp,
      dataJsonRow.sourceUniqueId,
      dataJsonRow.data,
      None
    )

  def fromDbModel(
      dataJsonRow: DataJsonRow,
      linkedDataJsonRows: Seq[DataJsonRow]): EndpointData =
    EndpointData(
      dataJsonRow.source,
      Some(dataJsonRow.recordId),
      dataJsonRow.sourceTimestamp,
      dataJsonRow.sourceUniqueId,
      dataJsonRow.data,
      Some(linkedDataJsonRows.map(fromDbModel))
    )

  def fromDbModel(dataBundleRow: DataBundlesRow): EndpointDataBundle = {
    import io.dataswift.models.hat.json.RichDataJsonFormats.propertyQueryFormat
    EndpointDataBundle(
      dataBundleRow.bundleId,
      dataBundleRow.bundle.as[Map[String, PropertyQuery]]
    )
  }

  def fromDbModel(
      dataDebitBundle: DataDebitBundleRow,
      bundle: DataBundlesRow,
      conditions: Option[DataBundlesRow]): DebitBundle =
    DebitBundle(
      dataDebitBundle.dateCreated,
      dataDebitBundle.startDate,
      dataDebitBundle.endDate,
      dataDebitBundle.rolling,
      dataDebitBundle.enabled,
      conditions.map(ModelTranslation.fromDbModel),
      ModelTranslation.fromDbModel(bundle)
    )

  def fromDbModel(
      dataDebit: DataDebitContractRow,
      client: UserUserRow,
      dataDebitBundle: Seq[
        (DataDebitBundleRow, DataBundlesRow, Option[DataBundlesRow])
      ]): RichDataDebit =
    RichDataDebit(
      dataDebit.dataDebitKey,
      dataDebit.dateCreated,
      userFromDbModel(client),
      dataDebitBundle.map(d => ModelTranslation.fromDbModel(d._1, d._2, d._3))
    )

  def fromDbModel(
      ddp: DataDebitPermissionsRow,
      bundle: DataBundlesRow,
      conditions: Option[DataBundlesRow]): ApiDataDebitPermissions =
    ApiDataDebitPermissions(
      ddp.dateCreated,
      ddp.purpose,
      ddp.start.toDateTime,
      Duration.standardSeconds(ddp.period),
      ddp.cancelAtPeriodEnd,
      ddp.canceledAt.map(_.toDateTime),
      ddp.termsUrl,
      conditions.map(fromDbModel),
      fromDbModel(bundle),
      ddp.accepted
    )

  def fromDbModel(
      dataDebit: DataDebitRow,
      dataDebitBundle: Seq[
        (DataDebitPermissionsRow, DataBundlesRow, Option[DataBundlesRow])
      ]): ApiDataDebit =
    ApiDataDebit(
      dataDebit.dataDebitKey,
      dataDebit.dateCreated,
      dataDebitBundle.map(d => ModelTranslation.fromDbModel(d._1, d._2, d._3)),
      dataDebit.requestClientName,
      dataDebit.requestClientUrl,
      dataDebit.requestClientLogoUrl,
      dataDebit.requestApplicationId,
      dataDebit.requestDescription
    )

  def userFromDbModel(user: UserUserRow): User =
    fromInternalModel(fromDbModel(user))

  @tailrec
  def groupRecords[T, U](
      list: Seq[(T, Option[U])],
      groups: Seq[(T, Seq[U])] = Seq()
    )(implicit equalIdentity: (T, T) => Boolean): Seq[(T, Seq[U])] =
    if (list.isEmpty)
      groups
    else
      groupRecords(
        list.dropWhile(v => equalIdentity(v._1, list.head._1)),
        groups :+ (
              (
                list.head._1,
                list
                  .takeWhile(v => equalIdentity(v._1, list.head._1))
                  .unzip
                  ._2
                  .flatten
              )
            )
      )
}
