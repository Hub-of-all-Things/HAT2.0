package org.hatdex.hat.she.mappers

import java.util.UUID

import scala.util.Try

import io.dataswift.models.hat.applications.{
  DataFeedItem,
  DataFeedItemContent,
  DataFeedItemLocation,
  DataFeedItemTitle,
  LocationGeo
}
import io.dataswift.models.hat.{ EndpointQuery, EndpointQueryFilter, FilterOperator, PropertyQuery }
import org.hatdex.hat.she.models.StaticDataValues
import org.joda.time.DateTime
import play.api.libs.json.{ JsError, JsSuccess, JsValue, Json }

class UberRidesMapper extends DataEndpointMapper {
  override protected val dataDeduplicationField: Option[String] = Some(
    "request_id"
  )

  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] = {
    val unixDateFilter = fromDate.flatMap { _ =>
      Some(
        FilterOperator.Between(
          Json.toJson(fromDate.map(t => t.getMillis / 1000)),
          Json.toJson(untilDate.map(t => t.getMillis / 1000))
        )
      )
    }

    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "uber/rides",
            None,
            unixDateFilter.map(f => Seq(EndpointQueryFilter("start_time", None, f))),
            None
          )
        ),
        Some("start_time"),
        Some("descending"),
        None
      )
    )
  }

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] = {
    logger.debug(s"uber content: $content")
    for {
      distance <- Try(
                    (content \ "distance").asOpt[Double].getOrElse(0.doubleValue()).toString
                  )
      startDate <- Try(
                     new DateTime((content \ "start_time").as[Long] * 1000.longValue())
                   )
      durationSeconds <- Try(
                           (content \ "end_time")
                             .asOpt[Int]
                             .getOrElse(0) - (content \ "start_time").asOpt[Int].getOrElse(0)
                         )
      duration <- Try {
                    val m = (durationSeconds / 60)      % 60
                    val h = (durationSeconds / 60 / 60) % 24
                    "%02d h %02d min".format(h, m)
                  }
      title <- Try(
                 DataFeedItemTitle(
                   s"Your trip on ${startDate.toString("dd/MM/YYYY")}",
                   None,
                   None
                 )
               )
      itemContent <- Try(
                       DataFeedItemContent(
                         Some(s"""${(content \ "start_city" \ "display_name")
                           .asOpt[String]
                           .getOrElse("Unknown City")},
             |${BigDecimal
                           .decimal(distance.toFloat)
                           .setScale(1, BigDecimal.RoundingMode.HALF_UP)
                           .toDouble} miles,
             |${duration}""".stripMargin),
                         None,
                         None,
                         None
                       )
                     )
      latitude <- Try(
                    (content \ "start_city" \ "latitude")
                      .asOpt[Double]
                      .getOrElse(0.doubleValue())
                  )
      longitude <- Try(
                     (content \ "start_city" \ "longitude")
                       .asOpt[Double]
                       .getOrElse(0.doubleValue())
                   )
      location <- Try(
                    DataFeedItemLocation(Some(LocationGeo(longitude, latitude)), None, None)
                  )
    } yield DataFeedItem(
      "uber",
      startDate,
      Seq(),
      Some(title),
      Some(itemContent),
      Some(location)
    )
  }
}

class UberProfileStaticDataMapper extends StaticDataEndpointMapper {
  def dataQueries(): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(EndpointQuery("uber/profile", None, None, None)),
        Some("dateCreated"),
        Some("descending"),
        Some(1)
      )
    )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      endpoint: String): Seq[StaticDataValues] = {
    val eventualData = content.validate[Map[String, JsValue]]
    eventualData match {
      case JsSuccess(value, _) =>
        val lastPartOfEndpointString = endpoint.split("/").last

        Seq(StaticDataValues(lastPartOfEndpointString, value))
      case e: JsError =>
        logger.error(s"Couldn't validate static data JSON for $endpoint. $e")
        Seq()
    }
  }
}
