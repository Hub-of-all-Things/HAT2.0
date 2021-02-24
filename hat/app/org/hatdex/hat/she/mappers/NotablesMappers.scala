package org.hatdex.hat.she.mappers

import java.util.UUID

import scala.util.Try

import io.dataswift.models.hat.applications.{
  DataFeedItem,
  DataFeedItemContent,
  DataFeedItemLocation,
  DataFeedItemMedia,
  DataFeedItemTitle,
  LocationGeo
}
import io.dataswift.models.hat.{ EndpointQuery, EndpointQueryFilter, PropertyQuery }
import org.joda.time.DateTime
import play.api.libs.json.JsValue

class NotablesFeedMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "rumpel/notablesv1",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("created_time", None, f))),
            None
          )
        ),
        Some("created_time"),
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
      title <- Try(
                 if ((content \ "currently_shared").as[Boolean])
                   DataFeedItemTitle("You posted", None, Some("public"))
                 else
                   DataFeedItemTitle("You posted", None, Some("private"))
               )
      itemContent <- Try(
                       if (
                         (content \ "photov1").isDefined && (content \ "photov1" \ "link")
                           .as[String]
                           .nonEmpty
                       )
                         DataFeedItemContent(
                           Some((content \ "message").as[String]),
                           None,
                           Some(
                             Seq(
                               DataFeedItemMedia(
                                 Some((content \ "photov1" \ "link").as[String]),
                                 Some((content \ "photov1" \ "link").as[String])
                               )
                             )
                           ),
                           None
                         )
                       else
                         DataFeedItemContent(
                           Some((content \ "message").as[String]),
                           None,
                           None,
                           None
                         )
                     )
      location <- Try(
                    if ((content \ "locationv1").isDefined)
                      Some(
                        DataFeedItemLocation(
                          Some(
                            LocationGeo(
                              (content \ "locationv1" \ "longitude").as[Double],
                              (content \ "locationv1" \ "latitude").as[Double]
                            )
                          ),
                          None,
                          None
                        )
                      )
                    else
                      None
                  )
      date <- Try((content \ "created_time").as[DateTime])
      tags <- Try((content \ "shared_on").as[Seq[String]])
    } yield DataFeedItem(
      "notables",
      date,
      tags,
      Some(title),
      Some(itemContent),
      location
    )
}
