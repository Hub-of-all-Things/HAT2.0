package org.hatdex.hat.she.mappers

import java.util.UUID

import scala.util.Try

import io.dataswift.models.hat.applications.{
  DataFeedItem,
  DataFeedItemContent,
  DataFeedItemLocation,
  DataFeedItemTitle,
  LocationAddress
}
import io.dataswift.models.hat.{ EndpointQuery, EndpointQueryFilter, FilterOperator, PropertyQuery }
import org.joda.time.{ DateTime, DateTimeZone }
import play.api.libs.json.{ JsValue, Json }

class GoogleCalendarMapper extends DataEndpointMapper {
  override protected val dataDeduplicationField: Option[String] = Some("id")

  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] = {
    val eventDateTimePropertyQuery = PropertyQuery(
      List(
        EndpointQuery(
          "calendar/google/events",
          None,
          Some(
            Seq(
              dateFilter(fromDate, untilDate).map(f => EndpointQueryFilter("start.dateTime", None, f))
            ).flatten
          ),
          None
        )
      ),
      Some("start.dateTime"),
      Some("descending"),
      None
    )

    val dateOnlyFilter =
      if (fromDate.isDefined)
        Some(
          FilterOperator.Between(
            Json.toJson(fromDate.map(_.toString("yyyy-MM-dd"))),
            Json.toJson(untilDate.map(_.toString("yyyy-MM-dd")))
          )
        )
      else
        None

    val eventDatePropertyQuery = PropertyQuery(
      List(
        EndpointQuery(
          "calendar/google/events",
          None,
          Some(
            Seq(
              dateOnlyFilter.map(f => EndpointQueryFilter("start.date", None, f))
            ).flatten
          ),
          None
        )
      ),
      Some("start.date"),
      Some("descending"),
      None
    )

    Seq(eventDateTimePropertyQuery, eventDatePropertyQuery)
  }

  def cleanHtmlTags(input: String): String =
    input
      .replaceAll("<br/?>", "\n")
      .replaceAll("&nbsp;", " ")
      .replaceAll("<a [^>]*>([^<]*)</a>", "$1")

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] =
    for {
      startDate <- Try(
                     (content \ "start" \ "dateTime")
                       .asOpt[DateTime]
                       .getOrElse((content \ "start" \ "date").as[DateTime])
                       .withZone(
                         (content \ "start" \ "timeZone")
                           .asOpt[String]
                           .flatMap(z => Try(DateTimeZone.forID(z)).toOption)
                           .getOrElse(DateTimeZone.getDefault)
                       )
                   )
      endDate <- Try(
                   (content \ "end" \ "dateTime")
                     .asOpt[DateTime]
                     .getOrElse((content \ "end" \ "date").as[DateTime])
                     .withZone(
                       (content \ "end" \ "timeZone")
                         .asOpt[String]
                         .flatMap(z => Try(DateTimeZone.forID(z)).toOption)
                         .getOrElse(DateTimeZone.getDefault)
                     )
                 )
      timeIntervalString <- Try(
                              eventTimeIntervalString(startDate, Some(endDate))
                            )
      itemContent <- Try(
                       DataFeedItemContent(
                         (content \ "description").asOpt[String].map(cleanHtmlTags),
                         None,
                         None,
                         None
                       )
                     )
      location <- Try(
                    DataFeedItemLocation(
                      geo = None,
                      address = (content \ "location")
                        .asOpt[String]
                        .map(l =>
                          LocationAddress(None, None, Some(l), None, None)
                        ), // TODO integrate with geocoding API for full location information?
                      tags = None
                    )
                  )
    } yield {
      val title = DataFeedItemTitle(
        s"${(content \ "summary").as[String]}",
        Some(
          s"${timeIntervalString._1} ${timeIntervalString._2.getOrElse("")}"
        ),
        Some("event")
      )
      val loc = Some(location).filter(l => l.address.isDefined || l.geo.isDefined || l.tags.isDefined)
      DataFeedItem(
        "google",
        startDate,
        Seq("event"),
        Some(title),
        Some(itemContent),
        loc
      )
    }
}
