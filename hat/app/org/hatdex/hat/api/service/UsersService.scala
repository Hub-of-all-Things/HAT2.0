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

package org.hatdex.hat.api.service

import java.util.UUID
import javax.inject.Inject

import scala.concurrent.Future
import scala.util.Success

import io.dataswift.models.hat.{ UserRole, _ }
import org.hatdex.hat.authentication.models.{ HatAccessLog, HatUser }
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.dal.Tables.{ UserRole => UserRoleDb, _ }
import org.hatdex.hat.resourceManagement.HatServer
import org.hatdex.libs.dal.HATPostgresProfile.api._
import org.joda.time.LocalDateTime
import play.api.Logger
import play.api.cache.AsyncCacheApi

class UsersService @Inject() (
    cache: AsyncCacheApi
  )(implicit ec: DalExecutionContext) {
  val logger: Logger = Logger(this.getClass)

  implicit def hatServer2db(implicit hatServer: HatServer): Database =
    hatServer.db

  def listUsers()(implicit server: HatServer): Future[Seq[HatUser]] =
    queryUser(UserUser)

  def getUser(
      userId: UUID
    )(implicit server: HatServer): Future[Option[HatUser]] =
    cache
      .get[HatUser](s"${server.domain}:user:$userId")
      .flatMap {
        case Some(cached) => Future.successful(Some(cached))
        case None =>
          queryUser(UserUser.filter(_.userId === userId))
            .map(_.headOption)
            .andThen({
              case Success(Some(u)) =>
                cache.set(s"${server.domain}:user:${u.userId}", u)
                cache.set(s"${server.domain}:user:${u.email}", u)
            })
      }

  def getUser(
      username: String
    )(implicit server: HatServer): Future[Option[HatUser]] =
    cache
      .get[HatUser](s"${server.domain}:user:$username")
      .flatMap {
        case Some(cached) => Future.successful(Some(cached))
        case None =>
          queryUser(UserUser.filter(_.email === username))
            .map(_.headOption)
            .andThen({
              case Success(Some(u)) =>
                cache.set(s"${server.domain}:user:${u.userId}", u)
                cache.set(s"${server.domain}:user:${u.email}", u)
            })
      }

  def getUserByRole(
      role: UserRole
    )(implicit server: HatServer): Future[Seq[HatUser]] = {
    val usersWithRole = UserRoleDb
      .filter(r => r.role === role.title && (r.extra.isEmpty || r.extra === role.extra))
      .map(_.userId)
    val query = UserUser.filter(_.userId in usersWithRole)
    queryUser(query)
  }

  private def queryUser(
      userFilter: Query[UserUser, UserUserRow, Seq]
    )(implicit db: Database): Future[Seq[HatUser]] = {
    val debits2 = DataDebitContract.map(d => (d.clientId.asColumnOf[String], d.dataDebitKey))

    val eventualUsers = queryUsers(userFilter)

    val userDataDebits = userFilter
      .joinLeft(debits2)
      .on(_.userId.asColumnOf[String] === _._1)

    for {
      users <- eventualUsers
      dataDebits <- db.run(userDataDebits.result)
    } yield users map { user =>
      val roles = dataDebits.filter(_._1.userId == user.userId) map { userDataDebit =>
        UserRole.userRoleDeserialize(
          "datadebit",
          userDataDebit._2.map(_._2)
        )
      }
      user.withRoles(roles: _*)
    }
  }

  implicit def equalDataJsonRowIdentity(
      a: UserUserRow,
      b: UserUserRow): Boolean =
    a.userId == b.userId

  private def queryUsers(
      userFilter: Query[UserUser, UserUserRow, Seq]
    )(implicit db: Database): Future[Seq[HatUser]] = {
    val query = userFilter
      .joinLeft(UserRoleDb)
      .on(_.userId === _.userId)
      .sortBy(_._1.userId)
    db.run(query.result) map { results =>
      ModelTranslation.groupRecords(results).map(ModelTranslation.fromDbModel)
    }
  }

  def saveUser(user: HatUser)(implicit server: HatServer): Future[HatUser] = {
    val userRow = UserUserRow(
      user.userId,
      LocalDateTime.now(),
      LocalDateTime.now(),
      user.email,
      user.pass, // The password is assumed to come in hashed, hence stored as is!
      user.name,
      enabled = user.enabled
    )
    val userRoleRows = user.roles map { role =>
      UserRoleRow(user.userId, role.title, role.extra)
    }

    val query = DBIO.seq(
      UserRoleDb.filter(_.userId === user.userId).delete,
      UserUser.insertOrUpdate(userRow),
      UserRoleDb ++= userRoleRows
    )

    val upsertedUser = server.db.run(query.transactionally)

    upsertedUser
      .map(_ => user)
      .andThen({
        case Success(saved) =>
          cache.set(s"${server.domain}:user:${saved.userId}", saved)
          cache.set(s"${server.domain}:user:${saved.email}", saved)
      })
  }

  def deleteUser(userId: UUID)(implicit server: HatServer): Future[Unit] =
    getUser(userId) flatMap {
        case Some(user) if user.roles.contains(Owner()) =>
          Future.failed(new RuntimeException("Can not delete owner user"))
        case Some(user) if user.roles.contains(Platform()) =>
          Future.failed(new RuntimeException("Can not delete platform user"))
        case None => Future.failed(new RuntimeException("User does not exist"))
        case Some(user) =>
          val deleteRoles = UserRoleDb.filter(_.userId === user.userId).delete
          val deleteUsers = UserUser.filter(_.userId === user.userId).delete
          server.db
            .run(DBIO.seq(deleteRoles, deleteUsers).transactionally)
            .map(_ => ())
            .andThen {
              case Success(_) =>
                cache.remove(s"${server.domain}:user:${user.userId}")
                cache.remove(s"${server.domain}:user:${user.email}")
            }
      }

  def changeUserState(
      userId: UUID,
      enabled: Boolean
    )(implicit server: HatServer): Future[Unit] =
    getUser(userId).flatMap {
      case Some(user) => saveUser(user.copy(enabled = enabled)).map(_ => ())
      case None       => Future.successful(())
    }

  def removeUser(username: String)(implicit server: HatServer): Future[Unit] = {
    val eventualUserIds =
      server.db.run(UserUser.filter(_.email === username).map(_.userId).result)
    eventualUserIds flatMap { userIds =>
      Future
        .sequence(userIds.map(deleteUser))
        .map(_ => ())
    }
  }

  def previousLogin(
      user: HatUser
    )(implicit server: HatServer): Future[Option[HatAccessLog]] = {
    logger.debug(s"Getting previous login for $user@${server.domain}")
    val query = for {
      access <- UserAccessLog
                  .filter(l => l.userId === user.userId)
                  .sortBy(_.date.desc)
                  .take(2)
                  .drop(1)
      user <- access.userUserFk
    } yield (access, user)
    server.db
      .run(query.result)
      .andThen {
        case Success(h) =>
          logger.error(s"Got previous logins $h @${server.domain}")
      }
      .map(_.headOption)
      .map(
        _.map(au =>
          ModelTranslation
            .fromDbModel(au._1, ModelTranslation.fromDbModel(au._2))
        )
      )
  }

  def logLogin(
      user: HatUser,
      loginType: String,
      scope: String,
      appName: Option[String],
      appResource: Option[String]
    )(implicit server: HatServer): Future[Unit] = {
    val accessLog = UserAccessLogRow(
      LocalDateTime.now(),
      user.userId,
      loginType,
      scope,
      appName,
      appResource
    )
    server.db.run(UserAccessLog += accessLog).map(_ => ())
  }

}
