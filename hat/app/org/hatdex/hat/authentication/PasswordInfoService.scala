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

package org.hatdex.hat.authentication

import javax.inject.Inject

import scala.concurrent.Future

import com.mohiva.play.silhouette.api.LoginInfo
import com.mohiva.play.silhouette.api.util.PasswordInfo
import com.mohiva.play.silhouette.password.BCryptPasswordHasher
import com.mohiva.play.silhouette.persistence.daos.DelegableAuthInfoDAO
import org.hatdex.hat.api.service.DalExecutionContext
import org.hatdex.hat.resourceManagement.HatServer
import play.api.Logger

class PasswordInfoService @Inject() (
    userService: AuthUserServiceImpl
  )(implicit ec: DalExecutionContext)
    extends DelegableAuthInfoDAO[PasswordInfo, HatServer] {

  val logger: Logger = Logger(this.getClass)

  def add(
      loginInfo: LoginInfo,
      authInfo: PasswordInfo
    )(implicit hat: HatServer): Future[PasswordInfo] =
    update(loginInfo, authInfo)

  def find(
      loginInfo: LoginInfo
    )(implicit hat: HatServer): Future[Option[PasswordInfo]] =
    userService.retrieve(loginInfo).map {
      case Some(user) if user.pass.isDefined =>
        Some(PasswordInfo(BCryptPasswordHasher.ID, user.pass.get, salt = None))
      case _ =>
        logger.info("No such user")
        None
    }

  def remove(loginInfo: LoginInfo)(implicit hat: HatServer): Future[Unit] =
    userService.remove(loginInfo)

  def save(
      loginInfo: LoginInfo,
      authInfo: PasswordInfo
    )(implicit hat: HatServer): Future[PasswordInfo] =
    find(loginInfo).flatMap {
      case Some(_) => update(loginInfo, authInfo)
      case None    => add(loginInfo, authInfo)
    }

  def update(
      loginInfo: LoginInfo,
      authInfo: PasswordInfo
    )(implicit hat: HatServer): Future[PasswordInfo] =
    userService.retrieve(loginInfo).map {
      case Some(user) =>
        userService.save(user.copy(pass = Some(authInfo.password)))
        authInfo
      case _ =>
        throw new Exception(
          "PasswordInfoDAO - update : the user must exists to update its password"
        )
    }

}
