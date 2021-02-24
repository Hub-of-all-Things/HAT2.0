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

package org.hatdex.hat.api.service

import javax.inject.Inject

import scala.concurrent._

import akka.Done
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.dal.Tables._
import org.hatdex.hat.phata.models.{ MailToken, MailTokenUser }
import org.hatdex.libs.dal.HATPostgresProfile.api._
import org.joda.time.LocalDateTime

trait MailTokenService[T <: MailToken] {
  def create(token: T)(implicit db: Database): Future[Option[T]]
  def retrieve(id: String)(implicit db: Database): Future[Option[T]]
  def retrieve(
      email: String,
      isSignup: Boolean
    )(implicit db: Database): Future[Option[T]]
  def consume(id: String)(implicit db: Database): Future[Done]
  def expire(id: String)(implicit db: Database): Future[Done]
}

class MailTokenUserService @Inject() (implicit val ec: DalExecutionContext) extends MailTokenService[MailTokenUser] {
  def create(
      token: MailTokenUser
    )(implicit db: Database): Future[Option[MailTokenUser]] =
    save(token).map(Some(_))
  def retrieve(
      id: String
    )(implicit db: Database): Future[Option[MailTokenUser]] =
    findById(id)
  def consume(id: String)(implicit db: Database): Future[Done] =
    delete(id)
  def retrieve(
      email: String,
      isSignup: Boolean
    )(implicit db: Database): Future[Option[MailTokenUser]] =
    findByEmailAndIsSignup(email, isSignup)
  def expire(id: String)(implicit db: Database): Future[Done] =
    expireNow(id)

  private def findById(
      id: String
    )(implicit db: Database): Future[Option[MailTokenUser]] =
    db.run(UserMailTokens.filter(_.id === id).result).map { tokens =>
      tokens.headOption.map(ModelTranslation.fromDbModel)
    }

  private def findByEmailAndIsSignup(
      email: String,
      isSignup: Boolean
    )(implicit db: Database): Future[Option[MailTokenUser]] =
    db.run(
      UserMailTokens
        .filter(t => t.email === email && t.isSignup === isSignup)
        .result
    ).map { tokens =>
      tokens.headOption.map(ModelTranslation.fromDbModel)
    }

  private def save(
      token: MailTokenUser
    )(implicit db: Database): Future[MailTokenUser] = {
    val query = (UserMailTokens returning UserMailTokens) += UserMailTokensRow(
            token.id,
            token.email,
            token.expirationTime.toLocalDateTime,
            token.isSignUp
          )
    db.run(query)
      .map(ModelTranslation.fromDbModel)
  }

  private def delete(id: String)(implicit db: Database): Future[Done] =
    db.run(UserMailTokens.filter(_.id === id).delete).map(_ => Done)

  private def expireNow(id: String)(implicit db: Database): Future[Done] =
    db.run(
      UserMailTokens
        .filter(_.id === id)
        .map(_.expirationTime)
        .update(LocalDateTime.now())
    ).map(_ => Done)
}
