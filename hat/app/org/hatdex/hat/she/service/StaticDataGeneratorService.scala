/*
 * Copyright (C) 2019 HAT Data Exchange Ltd
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
 * Written by Marios Tsekis <marios.tsekis@hatdex.org>
 * 2 / 2019
 */
package org.hatdex.hat.she.service

import javax.inject.Inject

import scala.concurrent.{ ExecutionContext, Future }

import org.hatdex.hat.api.service.richData.RichDataService
import org.hatdex.hat.resourceManagement.HatServer
import org.hatdex.hat.she.mappers.{
  FacebookProfileStaticDataMapper,
  FitbitProfileStaticDataMapper,
  InstagramProfileStaticDataMapper,
  SpotifyProfileStaticDataMapper,
  StaticDataEndpointMapper,
  TwitterProfileStaticDataMapper,
  UberProfileStaticDataMapper
}
import org.hatdex.hat.she.models.StaticDataValues
import play.api.Logger

class StaticDataGeneratorService @Inject() (
  )(implicit
    richDataService: RichDataService,
    val ec: ExecutionContext) {

  private val logger = Logger(this.getClass)

  private val staticDataMappers: Seq[(String, StaticDataEndpointMapper)] = Seq(
    "facebook/profile" -> new FacebookProfileStaticDataMapper(),
    "twitter/profile" -> new TwitterProfileStaticDataMapper(),
    "spotify/profile" -> new SpotifyProfileStaticDataMapper(),
    "fitbit/profile" -> new FitbitProfileStaticDataMapper(),
    "instagram/profile" -> new InstagramProfileStaticDataMapper(),
    "uber/profile" -> new UberProfileStaticDataMapper()
  )

  def getStaticData(
      endpoint: String
    )(implicit hatServer: HatServer): Future[Seq[StaticDataValues]] = {
    val mappers = staticDataMappers.find(_._1.startsWith(endpoint))

    logger.debug(s"Fetching feed data for ${mappers.map(_._1)}")

    mappers match {
      case Some((_, mapper)) => mapper.staticDataRecords()
      case None =>
        logger.info(s"No static data found for ${mappers.map(_._1)}")
        Future.successful(Seq())
    }
  }
}
