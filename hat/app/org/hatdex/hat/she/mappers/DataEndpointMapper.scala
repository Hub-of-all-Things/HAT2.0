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
 * 3 / 2018
 */

package org.hatdex.hat.she.mappers

import java.util.UUID

import scala.util.{ Success, Try }

import akka.NotUsed
import akka.stream.scaladsl.Source
import io.dataswift.models.hat._
import io.dataswift.models.hat.applications._
import org.hatdex.hat.api.service.richData.RichDataService
import org.hatdex.hat.resourceManagement.HatServer
import org.hatdex.hat.utils.SourceMergeSorter
import org.joda.time.DateTime
import org.joda.time.format.{ DateTimeFormatter, ISODateTimeFormat }
import play.api.Logger
import play.api.libs.json._

trait DataEndpointMapper extends JodaWrites with JodaReads {
  protected lazy val logger: Logger                    = Logger(this.getClass)
  protected val dateTimeFormat: DateTimeFormatter      = ISODateTimeFormat.dateTime()
  protected val dataDeduplicationField: Option[String] = None

  protected def dateFilter(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Option[FilterOperator.Operator] =
    fromDate.map { date =>
      FilterOperator.Between(
        Json.toJson(date.toString(dateTimeFormat)),
        Json.toJson(untilDate.map(_.toString(dateTimeFormat)))
      )
    }

  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery]
  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem]

  implicit private def dataFeedItemOrdering: Ordering[DataFeedItem] =
    Ordering.fromLessThan(_.date isAfter _.date)

  final def feed(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]
    )(implicit
      hatServer: HatServer,
      richDataService: RichDataService): Source[DataFeedItem, NotUsed] = {

    val feeds = dataQueries(fromDate, untilDate).map { query =>
      logger.debug(s"query is: $query")
      val dataSource: Source[EndpointData, NotUsed] =
        richDataService.propertyDataStreaming(
          query.endpoints,
          query.orderBy,
          orderingDescending = query.ordering.contains("descending"),
          skip = 0,
          limit = None,
          createdAfter = None
        )(hatServer.db)
      val deduplicated = dataDeduplicationField.map { field =>
        dataSource
          .sliding(2, 1)
          .collect({
            case Seq(a, b) if a.data \ field != b.data \ field => a
            case Seq(a) =>
              a // only a single element, e.g. last element in sliding window
          })
      } getOrElse {
        dataSource
      }

      deduplicated
        .sliding(2, 1)
        .map {
          case Seq(head, tail) =>
            val record = mapDataRecord(
              head.recordId.get,
              head.data,
              tail.recordId,
              Some(tail.data)
            )
            logger.debug(s"record is $record")
            record
          case Seq(item) =>
            val record = mapDataRecord(item.recordId.get, item.data)
            logger.debug(s"record is $record")
            record
        }
        .collect({
          case Success(x) => x
        })
    }

    new SourceMergeSorter().mergeWithSorter(feeds)
  }

  protected def eventTimeIntervalString(
      start: DateTime,
      end: Option[DateTime]): (String, Option[String]) = {
    val startString =
      if (start.getMillisOfDay == 0)
        s"${start.toString("dd MMMM")}"
      else
        s"${start.withZone(start.getZone).toString("dd MMMM HH:mm")}"

    val endString = end.map {
      case t if t.isAfter(start.withTimeAtStartOfDay().plusDays(1)) =>
        if (t.hourOfDay().get() == 0)
          s"- ${t.minusMinutes(1).toString("dd MMMM")}"
        else
          s"- ${t.withZone(start.getZone).toString("dd MMMM HH:mm ZZZ")}"
      case t if t.hourOfDay().get() == 0 => ""
      case t                             => s"- ${t.withZone(start.getZone).toString("HH:mm ZZZ")}"
    }

    (startString, endString)
  }

  protected def eventTimeIntervalString(
      start: Option[DateTime],
      end: Option[DateTime]): (Option[String], Option[String]) = {
    val startString = start.map {
      case t if t.getMillisOfDay == 0 => s"${t.toString("dd MMMM")}"
      case t                          => s"${t.withZone(t.getZone).toString("dd MMMM HH:mm")}"
    }

    val endString = (start, end) match {
      case (None, Some(t)) =>
        if (t.hourOfDay().get() == 0)
          Some(s"before ${t.minusMinutes(1).toString("dd MMMM")}")
        else
          Some(s"before ${t.toString("dd MMMM HH:mm z")}")
      case (Some(s), Some(t)) if t.isAfter(s.withTimeAtStartOfDay().plusDays(1)) =>
        if (t.hourOfDay().get() == 0)
          Some(s"- ${t.minusMinutes(1).toString("dd MMMM")}")
        else
          Some(s"- ${t.withZone(s.getZone).toString("dd MMMM HH:mm z")}")
      case (_, Some(t)) if t.hourOfDay.get == 0 => None
      case (Some(s), Some(t)) =>
        Some(s"- ${t.withZone(s.getZone).toString("HH:mm z")}")
      case (_, None) => None
    }

    (startString, endString)
  }
}

trait FeedItemComparator {
  def extractContent(
      content: JsValue,
      tailContent: JsValue,
      dataKey: String,
      dataKeyRoot: Option[String] = None): (JsLookupResult, JsLookupResult) = {
    val tailContentResult =
      if (dataKeyRoot.isEmpty) tailContent \ dataKey
      else tailContent \ dataKeyRoot.get \ dataKey
    val contentResult =
      if (dataKeyRoot.isEmpty) content \ dataKey
      else content \ dataKeyRoot.get \ dataKey

    (contentResult, tailContentResult)
  }

  def compareInt(
      content: JsValue,
      tailContent: JsValue,
      dataKey: String,
      humanKey: String,
      dataKeyRoot: Option[String] = None): (Boolean, String) = {
    val (contentResult, tailContentResult) =
      extractContent(content, tailContent, dataKey, dataKeyRoot)
    val previousValue = tailContentResult.asOpt[Int].getOrElse(0)
    val currentValue  = contentResult.asOpt[Int].getOrElse(0)
    val contentValue  = previousValue == currentValue
    val contentText =
      s"Your $humanKey has changed from $previousValue to $currentValue."
    (contentValue, contentText)
  }

  def compareString(
      content: JsValue,
      tailContent: JsValue,
      dataKey: String,
      humanKey: String,
      dataKeyRoot: Option[String] = None): (Boolean, String) = {
    val (contentResult, tailContentResult) =
      extractContent(content, tailContent, dataKey, dataKeyRoot)
    val previousValue = tailContentResult.asOpt[String].getOrElse("")
    val currentValue  = contentResult.asOpt[String].getOrElse("")
    val contentValue  = previousValue == currentValue
    val contentText =
      s"Your $humanKey has changed from $previousValue to $currentValue."
    (contentValue, contentText)
  }

  def compareFloat(
      content: JsValue,
      tailContent: JsValue,
      dataKey: String,
      humanKey: String,
      dataKeyRoot: Option[String] = None): (Boolean, String) = {
    val (contentResult, tailContentResult) =
      extractContent(content, tailContent, dataKey, dataKeyRoot)
    val previousValue = contentResult.asOpt[Float].getOrElse(0.0f)
    val currentValue  = tailContentResult.asOpt[Float].getOrElse(0.0f)
    val contentValue  = previousValue == currentValue
    val contentText =
      s"Your $humanKey has changed from $previousValue to $currentValue."
    (contentValue, contentText)
  }
}

class InsightSentimentMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "she/insights/emotions",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("timestamp", None, f))),
            None
          )
        ),
        Some("timestamp"),
        Some("descending"),
        None
      )
    )

  private val textMappings = Map(
    "twitter/tweets" -> "Twitter",
    "facebook/feed" -> "Facebook",
    "notables/feed" -> "Notables"
  )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] =
    for {
      sentiment <- Try((content \ "sentiment").as[String])
      text <- Try((content \ "text").as[String])
      source <- Try((content \ "source").as[String])
      timestamp <- Try((content \ "timestamp").as[DateTime])
    } yield {
      val title = DataFeedItemTitle(
        s"$sentiment Message",
        Some(s"on ${textMappings.getOrElse(source, source)}"),
        Some("sentiment")
      )

      val itemContent = DataFeedItemContent(
        text = Some(text),
        html = None,
        media = None,
        nestedStructure = None
      )

      DataFeedItem(
        "she",
        timestamp,
        Seq(
          "insight",
          "sentiment",
          sentiment,
          textMappings.getOrElse(source, source)
        ),
        Some(title),
        Some(itemContent),
        None
      )
    }
}

class InsightsMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "she/insights/activity-records",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("timestamp", None, f))),
            None
          )
        ),
        Some("timestamp"),
        Some("descending"),
        None
      )
    )

  private val textMappings = Map(
    "twitter/tweets" -> "Tweets sent",
    "facebook/feed" -> "Posts composed",
    "notables/feed" -> "Notes taken",
    "spotify/feed" -> "Songs listened to",
    "instagram/feed" -> "Photos uploaded",
    "fitbit/weight" -> "Fitbit weight records",
    "fitbit/sleep" -> "Fitbit sleep records",
    "fitbit/activity" -> "Fitbit activities logged",
    "uber/rides" -> "Trips taken",
    "calendar/google/events" -> "Calendar events recorded",
    "monzo/transactions" -> "Transactions performed",
    "she/insights/emotions" -> "Posts analysed for Sentiments",
    "she/insights/emotions/positive" -> "Positive",
    "she/insights/emotions/negative" -> "Negative",
    "she/insights/emotions/neutral" -> "Neutral"
  )

  private val sourceMappings = Map(
    "twitter/tweets" -> "twitter",
    "facebook/feed" -> "facebook",
    "notables/feed" -> "notables",
    "spotify/feed" -> "spotify",
    "instagram/feed" -> "instagram",
    "fitbit/weight" -> "fitbit-weight",
    "fitbit/sleep" -> "fitbit-sleep",
    "fitbit/activity" -> "fitbit-activity",
    "uber/rides" -> "uber",
    "calendar/google/events" -> "google",
    "monzo/transactions" -> "monzo",
    "she/insights/emotions" -> "sentiment",
    "she/insights/emotions/positive" -> "sentiment-positive",
    "she/insights/emotions/negative" -> "sentiment-negative",
    "she/insights/emotions/neutral" -> "sentiment-neutral"
  )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID],
      tailContent: Option[JsValue]): Try[DataFeedItem] =
    for {
      startDate <- Try((content \ "since").asOpt[DateTime])
      endDate <- Try((content \ "timestamp").asOpt[DateTime])
      timeIntervalString <- Try(eventTimeIntervalString(startDate, endDate))
      counters <- Try((content \ "counters").as[Map[String, Int]])
      if counters.exists(_._2 != 0)
    } yield {
      val title = DataFeedItemTitle(
        "Your recent activity summary",
        Some(
          s"${timeIntervalString._1.getOrElse("")} ${timeIntervalString._2.getOrElse("")}"
        ),
        Some("insight")
      )

      val nested: Map[String, Seq[DataFeedNestedStructureItem]] = counters
        .foldLeft(Seq[(String, DataFeedNestedStructureItem)]()) { (structured, newitem) =>
          val item = DataFeedNestedStructureItem(
            textMappings.getOrElse(newitem._1, "unrecognised"),
            Some(newitem._2.toString),
            None
          )
          val source = sourceMappings.getOrElse(newitem._1, "unrecognised")
          structured :+ (source -> item)
        }
        .filterNot(_._2.content == "unrecognised")
        .filterNot(_._2.badge.contains("0"))
        .groupBy(_._1)
        .map({
          case (k, v) => k -> v.unzip._2
        })

      val simplified: String = nested
        .map({
          case (source, info) =>
            s"""${source.capitalize}:
           |  ${info
              .map(i => s"${i.content}: ${i.badge.getOrElse("")}")
              .mkString("\n  ")}
           |""".stripMargin
        })
        .mkString("\n")

      val itemContent = DataFeedItemContent(
        text = Some(simplified),
        html = None,
        media = None,
        nestedStructure = Some(nested)
      )

      DataFeedItem(
        "she",
        endDate.getOrElse(DateTime.now()),
        Seq("insight", "activity"),
        Some(title),
        Some(itemContent),
        None
      )
    }
}

class DropsTwitterWordcloudMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "drops/insights/twitter/word-cloud",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("timestamp", None, f))),
            None
          )
        ),
        Some("timestamp"),
        Some("descending"),
        None
      )
    )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] =
    for {
      counters <- Try((content \ "summary" \ "totalCount").as[Int])
      if counters > 0
      _ = counters // Workaround scala/bug#11175 -Ywarn-unused:params false positive
    } yield {
      val title = DataFeedItemTitle(
        "Twitter Word Cloud",
        None,
        Some("twitter-word-cloud")
      )
      val itemContent = DataFeedItemContent(
        text = Some(content.toString()),
        html = None,
        media = None,
        nestedStructure = None
      )
      DataFeedItem(
        "drops",
        DateTime.now,
        Seq("wordcloud", "twitter-word-cloud"),
        Some(title),
        Some(itemContent),
        None
      )
    }
}

class DropsSentimentHistoryMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "drops/insights/sentiment-history",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("timestamp", None, f))),
            None
          )
        ),
        Some("timestamp"),
        Some("descending"),
        None
      )
    )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] =
    for {
      counters <- Try((content \ "summary" \ "totalCount").as[Int])
      if counters > 0
      _ = counters // Workaround scala/bug#11175 -Ywarn-unused:params false positive
    } yield {
      val title =
        DataFeedItemTitle("Sentiment History", None, Some("sentiment-history"))
      val itemContent = DataFeedItemContent(
        text = Some(content.toString()),
        html = None,
        media = None,
        nestedStructure = None
      )
      DataFeedItem(
        "drops",
        DateTime.now,
        Seq("sentiment-history", "sentiment-history"),
        Some(title),
        Some(itemContent),
        None
      )
    }
}

class InsightCommonLocationsMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "she/insights/common-locations",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("dateCreated", None, f))),
            None
          )
        ),
        Some("timestamp"),
        Some("descending"),
        None
      )
    )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] =
    for {
      counters <- Try((content \ "summary" \ "totalCount").as[Int])
      if counters > 0
      _ = counters // Workaround scala/bug#11175 -Ywarn-unused:params false positive
    } yield {
      val title =
        DataFeedItemTitle("Common Locations", None, Some("common-locations"))
      val itemContent = DataFeedItemContent(
        text = Some(content.toString()),
        html = None,
        media = None,
        nestedStructure = None
      )
      DataFeedItem(
        "she",
        DateTime.now,
        Seq("common-locations", "common-locations"),
        Some(title),
        Some(itemContent),
        None
      )
    }
}
