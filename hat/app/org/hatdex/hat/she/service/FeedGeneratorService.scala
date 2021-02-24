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

package org.hatdex.hat.she.service

import javax.inject.Inject

import scala.concurrent.duration._
import scala.concurrent.{ ExecutionContext, Future }
import scala.util.{ Success, Try }

import akka.NotUsed
import akka.actor.ActorSystem
import akka.stream._
import akka.stream.scaladsl.{ Sink, Source }
import io.dataswift.models.hat._
import io.dataswift.models.hat.applications.{ DataFeedItem, DataFeedItemLocation, LocationGeo }
import org.hatdex.hat.api.service.richData.RichDataService
import org.hatdex.hat.resourceManagement.HatServer
import org.hatdex.hat.she.mappers._
import org.hatdex.hat.utils.{ SourceAugmenter, SourceMergeSorter }
import org.joda.time.DateTime
import play.api.Logger
import play.api.libs.json.JsNumber

class FeedGeneratorService @Inject() (
  )(implicit
    richDataService: RichDataService,
    val actorSystem: ActorSystem,
    val ec: ExecutionContext) {

  private val logger                                     = Logger(this.getClass)
  implicit protected val materializer: ActorMaterializer = ActorMaterializer()

  private val dataMappers: Seq[(String, DataEndpointMapper)] = Seq(
    "facebook/profile" -> new FacebookProfileMapper(),
    "facebook/feed" -> new FacebookFeedMapper(),
    "facebook/likes/pages" -> new FacebookPagesLikesMapper(),
    "facebook/events" -> new FacebookEventMapper(),
    "twitter/profile" -> new TwitterProfileMapper(),
    "twitter/tweets" -> new TwitterFeedMapper(),
    "fitbit/profile" -> new FitbitProfileMapper(),
    "fitbit/sleep" -> new FitbitSleepMapper(),
    "fitbit/weight" -> new FitbitWeightMapper(),
    "fitbit/activity" -> new FitbitActivityMapper(),
    "fitbit/activity/day/summary" -> new FitbitActivityDaySummaryMapper(),
    "calendar/google/events" -> new GoogleCalendarMapper(),
    "notables/feed" -> new NotablesFeedMapper(),
    "spotify/feed" -> new SpotifyFeedMapper(),
    "monzo/transactions" -> new MonzoTransactionMapper(),
    "instagram/feed" -> new InstagramMediaMapper(),
    "uber/rides" -> new UberRidesMapper()
  )

  private val insightMappers: Seq[(String, DataEndpointMapper)] = Seq(
    "she/activity-records" -> new InsightsMapper(),
    "she/sentiments" -> new InsightSentimentMapper(),
    "drops/twitter/word-cloud" -> new DropsTwitterWordcloudMapper(),
    "drops/sentiment-history" -> new DropsSentimentHistoryMapper(),
    "she/common-locations" -> new InsightCommonLocationsMapper()
  )

  def getFeed(
      endpoint: String,
      since: Option[Long],
      until: Option[Long],
      mergeLocations: Boolean = false
    )(implicit hatServer: HatServer): Future[Seq[DataFeedItem]] =
    if (endpoint.startsWith("she"))
      insights(since, until, Some(endpoint)).runWith(Sink.seq)
    else
      feedForMappers(
        dataMappers.filter(_._1.startsWith(endpoint)),
        since,
        until,
        mergeLocations,
        includeInsights = false
      )

  def fullFeed(
      since: Option[Long],
      until: Option[Long],
      mergeLocations: Boolean = false
    )(implicit hatServer: HatServer): Future[Seq[DataFeedItem]] =
    feedForMappers(
      dataMappers,
      since,
      until,
      mergeLocations,
      includeInsights = true
    )

  def insights(
      since: Option[Long],
      until: Option[Long],
      endpoint: Option[String]
    )(implicit hatServer: HatServer): Source[DataFeedItem, NotUsed] = {
    val now = DateTime.now()
    val sinceTime = since
      .map(t => new DateTime(t * 1000L))
      .getOrElse(now.minus(defaultTimeBack.toMillis))
    val untilTime = until
      .map(t => new DateTime(t * 1000L))
      .getOrElse(now.plus(defaultTimeForward.toMillis))

    val sources: Seq[Source[DataFeedItem, NotUsed]] =
      endpoint
        .fold(insightMappers)(e => insightMappers.filter(_._1.startsWith(e)))
        .unzip
        ._2
        .map(_.feed(Some(sinceTime), Some(untilTime)))

    new SourceMergeSorter()
      .mergeWithSorter(sources)
  }

  private val defaultTimeBack    = 180.days
  private val defaultTimeForward = 30.days
  protected def feedForMappers(
      mappers: Seq[(String, DataEndpointMapper)],
      since: Option[Long],
      until: Option[Long],
      mergeLocations: Boolean,
      includeInsights: Boolean
    )(implicit
      hatServer: HatServer): Future[Seq[DataFeedItem]] = {
    logger.debug(s"Fetching feed data for ${mappers.unzip._1}")
    val now = DateTime.now()
    val sinceTime = since
      .map(t => new DateTime(t * 1000L))
      .getOrElse(now.minus(defaultTimeBack.toMillis))
    val untilTime = until
      .map(t => new DateTime(t * 1000L))
      .getOrElse(now.plus(defaultTimeForward.toMillis))
    val sources: Seq[Source[DataFeedItem, NotUsed]] = mappers.unzip._2
      .map(_.feed(Some(sinceTime), Some(untilTime)))

    val sortedSources = new SourceMergeSorter()
      .mergeWithSorter(sources)

    val geotaggedStream = if (mergeLocations) {
      val locations =
        locationStream(sinceTime.getMillis / 1000L, untilTime.getMillis / 1000L)
      new SourceAugmenter().augment(
        sortedSources,
        locations.sliding(2, 1),
        locationAugmentFunction
      )
    } else
      sortedSources

    val outputStream =
      if (includeInsights)
        new SourceMergeSorter()
          .mergeWithSorter(Seq(geotaggedStream, insights(since, until, None)))
      else
        geotaggedStream

    outputStream
      .runWith(Sink.seq)
  }

  def locationStream(
      since: Long,
      until: Long
    )(implicit hatServer: HatServer): Source[(DateTime, LocationGeo), NotUsed] = {
    val endpoint = "rumpel/locations/ios"
    val endpointQuery = EndpointQuery(
      endpoint,
      None,
      Some(
        Seq(
          EndpointQueryFilter(
            "dateCreated",
            None,
            FilterOperator.Between(JsNumber(since), JsNumber(until))
          )
        )
      ),
      None
    )
    val query = PropertyQuery(
      List(endpointQuery),
      Some("dateCreated"),
      Some("descending"),
      None
    )

    val eventualFeed: Source[EndpointData, NotUsed] =
      richDataService.propertyDataStreaming(
        query.endpoints,
        query.orderBy,
        orderingDescending = query.ordering.contains("descending"),
        skip = 0,
        limit = None,
        createdAfter = None
      )(hatServer.db)

    eventualFeed
      .map(d =>
        Try(
          new DateTime(
            (d.data \ "dateCreated").as[Long] * 1000L
          ) -> LocationGeo(
                (d.data \ "longitude").as[Double],
                (d.data \ "latitude").as[Double]
              )
        )
      )
      .collect({
        case Success(x) => x
      })
  }

  implicit protected def dataFeedItemOrdering: Ordering[DataFeedItem] =
    Ordering.fromLessThan(_.date isAfter _.date)

  private def locationAugmentFunction(
      feedItem: DataFeedItem,
      locations: Seq[(DateTime, LocationGeo)]): Either[DataFeedItem, Seq[(DateTime, LocationGeo)]] =
    //    logger.debug(s"Dispatching event for $feedItem with $locations")
    if (feedItem.location.isDefined)
      //      logger.debug("Location defined, skip")
      Left(feedItem)
    else {
      val feedItemInstance      = feedItem.date.getMillis
      val startLocationInstance = locations.head._1.getMillis
      val endLocationInstance   = locations.last._1.getMillis
      if (feedItemInstance < startLocationInstance && feedItemInstance > endLocationInstance) {
        val closest = interpolateLocation(
          feedItemInstance,
          (startLocationInstance, locations.head._2),
          (endLocationInstance, locations.last._2)
        )
        Left(
          feedItem.copy(location = closest.map(l => DataFeedItemLocation(Some(l), None, None)))
        )
      } else if (feedItemInstance > startLocationInstance) {
        val closest = interpolateLocation(
          feedItemInstance,
          (startLocationInstance, locations.head._2),
          (endLocationInstance, locations.last._2)
        )
        Left(
          feedItem.copy(location = closest.map(l => DataFeedItemLocation(Some(l), None, None)))
        )
      } else
        //        logger.debug(s"Item older than location, find new location")
        Right(locations)
    }

  private def interpolateLocation(
      anchorInstance: Long,
      startItem: (Long, LocationGeo),
      endItem: (Long, LocationGeo)): Option[LocationGeo] = {
    val timeDiffStart = Math.abs(anchorInstance - startItem._1)
    val timeDiffEnd   = Math.abs(anchorInstance - endItem._1)
    val timeBound     = 7.hours.toMillis
    if (timeDiffStart < timeBound || timeDiffEnd < timeBound) { // if either location is sufficiently close
      val ratio =
        timeDiffStart.toDouble / (timeDiffStart + timeDiffEnd).toDouble
      Some(
        LocationGeo(
          startItem._2.longitude * (1 - ratio) + endItem._2.longitude * ratio,
          startItem._2.latitude * (1 - ratio) + endItem._2.latitude * ratio
        )
      )
    } else
      None
  }

}
