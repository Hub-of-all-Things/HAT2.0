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
 * 8 / 2017
 */

package org.hatdex.hat

import javax.inject.Singleton

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.concurrent.duration.Duration
import scala.reflect.ClassTag

import akka.Done
import play.api.cache.AsyncCacheApi

@Singleton
class FakeCache extends AsyncCacheApi {

  private var store = Map[String, Any]()

  override def set(key: String, value: Any, expiration: Duration): Future[Done] =
    Future(store = store + (key -> value)).map(_ => Done)

  override def get[T](key: String)(implicit evidence$2: ClassTag[T]): Future[Option[T]] =
    Future(store.get(key).asInstanceOf[Option[T]])

  override def getOrElseUpdate[A](key: String, expiration: Duration)(orElse: => Future[A])(implicit evidence$1: ClassTag[A]): Future[A] =
    Future(store.get(key).asInstanceOf[Option[A]])
      .flatMap(_.map(Future.successful(_)).getOrElse(orElse))

  override def remove(key: String): Future[Done] =
    Future(store = store - key).map(_ => Done)

  override def removeAll(): Future[Done] =
    Future(store = Map[String, Any]()).map(_ => Done)
}
