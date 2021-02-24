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
 * 6 / 2018
 */
package org.hatdex.hat.phata.controllers

import javax.inject.Inject

import scala.concurrent.Future

import play.api.mvc._

class WellKnown @Inject() (components: ControllerComponents) extends AbstractController(components) {

  def appleAppSiteAssociation(): EssentialAction =
    Action.async { _ =>
      val webCredentials =
        """
          |{
          |  "applinks": {
          |    "apps": [],
          |    "details": [
          |    {
          |      "appID": "84XHE3A5BA.com.hubofallthings.hatappbeta",
          |      "paths": ["*"]
          |    },
          |    {
          |      "appID": "84XHE3A5BA.com.hubofallthings.hatapp",
          |      "paths": ["*"]
          |    }
          |    ]
          |  }
          |}
        """.stripMargin

      Future.successful(Ok(webCredentials))
    }
}
