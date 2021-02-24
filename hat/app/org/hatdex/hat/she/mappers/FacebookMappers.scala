package org.hatdex.hat.she.mappers

import java.util.UUID

import scala.util.{ Failure, Try }

import io.dataswift.models.hat.applications.{
  DataFeedItem,
  DataFeedItemContent,
  DataFeedItemLocation,
  DataFeedItemMedia,
  DataFeedItemTitle,
  LocationAddress,
  LocationGeo
}
import io.dataswift.models.hat.{ EndpointQuery, EndpointQueryFilter, PropertyQuery }
import org.hatdex.hat.she.models.StaticDataValues
import org.joda.time.DateTime
import play.api.libs.json.{ JsError, JsObject, JsString, JsSuccess, JsValue }

class FacebookProfileMapper extends DataEndpointMapper with FeedItemComparator {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "facebook/profile",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("hat_updated_time", None, f))),
            None
          )
        ),
        Some("hat_updated_time"),
        Some("descending"),
        None
      )
    )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] = {
    val comparison =
      compare(content, tailContent).filter(
        _._1 == false
      ) // remove all fields that have the same values pre/current
    if (comparison.isEmpty)
      Failure(new RuntimeException("Comparision Failure. Data the same"))
    else
      for {
        title <- Try(
                   DataFeedItemTitle("Your Facebook Profile has changed.", None, None)
                 )
        itemContent <- {
          val contentText = comparison.map(item => s"${item._2}\n").mkString
          Try(DataFeedItemContent(Some(contentText), None, None, None))
        }
      } yield DataFeedItem(
        "facebook",
        (tailContent.getOrElse(content) \ "hat_updated_time").as[DateTime],
        Seq("profile"),
        Some(title),
        Some(itemContent),
        None
      )
  }

  def compare(
      content: JsValue,
      tailContent: Option[JsValue]): Seq[(Boolean, String)] =
    if (tailContent.isEmpty)
      Seq()
    else
      Seq(
        compareString(content, tailContent.get, "name", "Name"),
        compareString(content, tailContent.get, "gender", "Gender"),
        compareString(content, tailContent.get, "age_range", "Age Range"),
        compareInt(
          content,
          tailContent.get,
          "friend_count",
          "Number of Friends"
        )
      )
}

class FacebookEventMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "facebook/events",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("start_time", None, f))),
            None
          )
        ),
        Some("start_time"),
        None,
        None
      )
    )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] =
    for {
      timeIntervalString <- Try(
                              eventTimeIntervalString(
                                (content \ "start_time").as[DateTime],
                                Some((content \ "end_time").as[DateTime])
                              )
                            )

      itemContent <- Try(
                       DataFeedItemContent(
                         Some((content \ "description").as[String]),
                         None,
                         None,
                         None
                       )
                     )
      title <- Try(
                 if ((content \ "rsvp_status").as[String] == "attending")
                   DataFeedItemTitle(
                     "You are attending an event",
                     Some(
                       s"${timeIntervalString._1} ${timeIntervalString._2.getOrElse("")}"
                     ),
                     Some("event")
                   )
                 else
                   DataFeedItemTitle(
                     "You have an event",
                     Some(
                       s"${timeIntervalString._1} ${timeIntervalString._2.getOrElse("")}"
                     ),
                     Some("event")
                   )
               )
    } yield {
      val location = Try(
        DataFeedItemLocation(
          geo = (content \ "place")
            .asOpt[JsObject]
            .map(location =>
              LocationGeo(
                (location \ "location" \ "longitude").as[String].toDouble,
                (location \ "location" \ "latitude").as[String].toDouble
              )
            ),
          address = (content \ "place")
            .asOpt[JsObject]
            .map(location =>
              LocationAddress(
                (location \ "location" \ "country").asOpt[String],
                (location \ "location" \ "city").asOpt[String],
                (location \ "name").asOpt[String],
                (location \ "location" \ "street").asOpt[String],
                (location \ "location" \ "zip").asOpt[String]
              )
            ),
          tags = None
        )
      ).toOption
        .filter(l => l.address.isDefined || l.geo.isDefined || l.tags.isDefined)

      DataFeedItem(
        "facebook",
        (content \ "start_time").as[DateTime],
        Seq("event"),
        Some(title),
        Some(itemContent),
        location
      )
    }
}

class FacebookFeedMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "facebook/feed",
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
                 if ((content \ "type").as[String] == "photo")
                   DataFeedItemTitle("You posted a photo", None, Some("photo"))
                 else if ((content \ "type").as[String] == "link")
                   DataFeedItemTitle("You shared a story", None, None)
                 else
                   DataFeedItemTitle("You posted", None, None)
               )
      media <- Try(
                 (content \ "picture")
                   .asOpt[String]
                   .map(url =>
                     List(
                       DataFeedItemMedia(
                         Some(url),
                         (content \ "full_picture").asOpt[String]
                       )
                     )
                   )
                   .getOrElse {
                     List(
                       DataFeedItemMedia(None, (content \ "full_picture").asOpt[String])
                     )
                   }
               )
      itemContent <- Try(
                       DataFeedItemContent(
                         Some(s"""${(content \ "message")
                           .asOpt[String]
                           .getOrElse(
                             (content \ "story")
                               .asOpt[String]
                               .getOrElse((content \ "description").as[String])
                           )}
             |
             |${(content \ "link")
                           .asOpt[String]
                           .getOrElse("")}""".stripMargin.trim),
                         None,
                         Some(media),
                         None
                       )
                     )
      date <- Try((content \ "created_time").as[DateTime])
      tags <- Try(Seq("post", (content \ "type").as[String]))
    } yield {

      val locationGeo = Try(
        LocationGeo(
          (content \ "place" \ "location" \ "longitude").as[Double],
          (content \ "place" \ "location" \ "latitude").as[Double]
        )
      ).toOption

      val locationAddress = Try(
        LocationAddress(
          (content \ "place" \ "location" \ "country").asOpt[String],
          (content \ "place" \ "location" \ "city").asOpt[String],
          (content \ "place" \ "name").asOpt[String],
          (content \ "place" \ "location" \ "street").asOpt[String],
          (content \ "place" \ "location" \ "zip").asOpt[String]
        )
      ).toOption

      val maybeLocation =
        if (
          locationAddress.contains(
            LocationAddress(None, None, None, None, None)
          )
        )
          None
        else
          locationAddress

      val location = locationGeo
        .orElse(maybeLocation)
        .map(_ => DataFeedItemLocation(locationGeo, maybeLocation, None))

      DataFeedItem(
        "facebook",
        date,
        tags,
        Some(title),
        Some(itemContent),
        location
      )
    }
}

class FacebookPagesLikesMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "facebook/likes/pages",
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
      name <- Try((content \ "name").as[String])
      title <- Try(DataFeedItemTitle(s"You liked $name", None, None))

      itemContent <- Try(
                       DataFeedItemContent(
                         Some(s"""Page Name - $name
             |
             |Location - ${(content \ "location" \ "city")
                           .asOpt[String]
                           .getOrElse("")}
             |Website - ${(content \ "website")
                           .asOpt[String]
                           .getOrElse("")}""".stripMargin.trim),
                         None,
                         None,
                         None
                       )
                     )
      date <- Try((content \ "created_time").as[DateTime])
      tags <- Try(Seq("page", name))
    } yield {

      val locationGeo = Try(
        LocationGeo(
          (content \ "location" \ "longitude").as[Double],
          (content \ "location" \ "latitude").as[Double]
        )
      ).toOption

      val locationAddress = Try(
        LocationAddress(
          (content \ "location" \ "country").asOpt[String],
          (content \ "location" \ "city").asOpt[String],
          (content \ "name").asOpt[String],
          (content \ "location" \ "street").asOpt[String],
          (content \ "location" \ "zip").asOpt[String]
        )
      ).toOption

      val maybeLocation =
        if (
          locationAddress.contains(
            LocationAddress(None, None, None, None, None)
          )
        )
          None
        else
          locationAddress

      val location = locationGeo
        .orElse(maybeLocation)
        .map(_ => DataFeedItemLocation(locationGeo, maybeLocation, None))

      DataFeedItem(
        "facebook",
        date,
        tags,
        Some(title),
        Some(itemContent),
        location
      )
    }
}

class FacebookProfileStaticDataMapper extends StaticDataEndpointMapper {
  def dataQueries(): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(EndpointQuery("facebook/profile", None, None, None)),
        Some("hat_updated_time"),
        Some("descending"),
        Some(1)
      ),
      PropertyQuery(
        List(EndpointQuery("facebook/likes/pages", None, None, None)),
        Some("created_time"),
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
        if (endpoint.contains("likes")) {

          val numberOfPagesLiked =
            value.filterKeys(key => key == "number_of_pages_liked")
          if (numberOfPagesLiked.isEmpty)
            Seq()
          else
            Seq(StaticDataValues(lastPartOfEndpointString, numberOfPagesLiked))
        } else {
          val updatedValue = value
            .get("location")
            .flatMap(v => (v \ "name").asOpt[String])
            .map(locationName => value ++ Map("location" -> JsString(locationName)))
            .getOrElse(value)
          Seq(
            StaticDataValues(
              lastPartOfEndpointString,
              updatedValue.filterKeys(key => key != "friends" && key != "languages")
            )
          )
        }
      case e: JsError =>
        logger.error(s"Couldn't validate static data JSON for $endpoint. $e")
        Seq()
    }
  }
}
