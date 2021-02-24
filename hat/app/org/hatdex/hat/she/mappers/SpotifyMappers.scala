package org.hatdex.hat.she.mappers

import java.util.UUID

import scala.util.Try

import io.dataswift.models.hat.applications.{
  DataFeedItem,
  DataFeedItemContent,
  DataFeedItemMedia,
  DataFeedItemTitle
}
import io.dataswift.models.hat.{ EndpointQuery, EndpointQueryFilter, PropertyQuery }
import org.hatdex.hat.she.models.StaticDataValues
import org.joda.time.DateTime
import play.api.libs.json.{ __, JsError, JsNumber, JsObject, JsResult, JsSuccess, JsValue }

class SpotifyFeedMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "spotify/feed",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("played_at", None, f))),
            None
          )
        ),
        Some("played_at"),
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
      durationSeconds <- Try((content \ "track" \ "duration_ms").as[Int] / 1000)
      title <- Try(
                 DataFeedItemTitle(
                   "You listened",
                   None,
                   Some(
                     s"${"%02d".format(durationSeconds / 60)}:${"%02d".format(durationSeconds % 60)}"
                   )
                 )
               )
      itemContent <- Try(
                       DataFeedItemContent(
                         Some(s"""${(content \ "track" \ "name").as[String]},
             |${(content \ "track" \ "artists")
                           .as[Seq[JsObject]]
                           .map(a => (a \ "name").as[String])
                           .mkString(", ")},
             |${(content \ "track" \ "album" \ "name")
                           .as[String]}""".stripMargin),
                         None,
                         Some(
                           Seq(
                             DataFeedItemMedia(
                               (content \ "track" \ "album" \ "images" \ 0 \ "url")
                                 .asOpt[String],
                               (content \ "track" \ "album" \ "images" \ 0 \ "url")
                                 .asOpt[String]
                             )
                           )
                         ),
                         None
                       )
                     )
      date <- Try((content \ "played_at").as[DateTime])
    } yield DataFeedItem(
      "spotify",
      date,
      Seq(),
      Some(title),
      Some(itemContent),
      None
    )
}

class SpotifyProfileStaticDataMapper extends StaticDataEndpointMapper {
  def dataQueries(): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(EndpointQuery("spotify/profile", None, None, None)),
        Some("dateCreated"),
        Some("descending"),
        Some(1)
      )
    )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      endpoint: String): Seq[StaticDataValues] = {
    val eventualData = content.validate[JsObject]
    eventualData match {
      case JsSuccess(value, _) =>
        val lastPartOfEndpointString = endpoint.split("/").last
        val maybeTransformedData     = transformData(value).flatMap(item => item.validate[Map[String, JsValue]])
        maybeTransformedData match {
          case JsSuccess(data, _) =>
            Seq(
              StaticDataValues(
                lastPartOfEndpointString,
                (data - "images" - "external_urls")
              )
            )
          case e: JsError =>
            logger.error(
              s"Couldn't validate static data JSON for $endpoint. $e"
            )
            Seq()
        }
      case e: JsError =>
        logger.error(s"Couldn't validate static data JSON for $endpoint. $e")
        Seq()
    }
  }

  private def transformData(rawData: JsObject): JsResult[JsValue] = {
    val transformation = __.json.update(
      __.read[JsObject]
        .map { profile =>
          val followers = (profile \ "followers" \ "total")
            .asOpt[JsNumber]
            .getOrElse(JsNumber(0))

          profile ++ JsObject(Map("followers" -> followers))
        }
    )

    rawData.transform(transformation)
  }
}
