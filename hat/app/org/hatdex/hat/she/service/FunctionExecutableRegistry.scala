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
 * 11 / 2017
 */

package org.hatdex.hat.she.service

import scala.reflect.ClassTag

import org.apache.commons.lang3.reflect.TypeUtils
import org.hatdex.hat.she.models.FunctionExecutable

class FunctionExecutableRegistry(interfaces: Seq[FunctionExecutable]) {

  /**
    * Gets a specific function by its type.
    *
    * @tparam T The type of the provider.
    * @return Some specific FunctionExecutable or None if no function for the given type could be found.
    */
  def get[T <: FunctionExecutable: ClassTag]: Option[T] =
    interfaces
      .find(p => TypeUtils.isInstance(p, implicitly[ClassTag[T]].runtimeClass))
      .map(_.asInstanceOf[T])

  /**
    * Gets a specific function by its name.
    *
    * @param id The ID of the provider to return.
    * @return Some specific FunctionExecutable or None if no function for the given name could be found.
    */
  def get[T <: FunctionExecutable: ClassTag](id: String): Option[T] =
    getSeq[T].find(_.configuration.id == id)

  /**
    * Gets a list of function that match a certain type.
    *
    * @tparam T The type of the provider.
    * @return A list of functions that match a certain type.
    */
  def getSeq[T <: FunctionExecutable: ClassTag]: Seq[T] =
    interfaces
      .filter(p => TypeUtils.isInstance(p, implicitly[ClassTag[T]].runtimeClass))
      .map(_.asInstanceOf[T])
}
