package org.hatdex.hat.she.mappers

import java.util.UUID

import scala.util.{ Failure, Try }

import io.dataswift.models.hat.applications.{
  DataFeedItem,
  DataFeedItemContent,
  DataFeedItemLocation,
  DataFeedItemTitle,
  LocationAddress,
  LocationGeo
}
import io.dataswift.models.hat.{ EndpointQuery, EndpointQueryFilter, PropertyQuery }
import org.hatdex.hat.she.models.StaticDataValues
import org.joda.time.DateTime
import play.api.libs.json.{ JsNull, JsObject, JsValue }

class TwitterProfileMapper extends DataEndpointMapper with FeedItemComparator {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "twitter/tweets",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("lastUpdated", None, f))),
            None
          )
        ),
        Some("lastUpdated"),
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
                   DataFeedItemTitle("Your Twitter Profile has changed.", None, None)
                 )
        itemContent <- {
          val contentText = comparison.map(item => s"${item._2}\n").mkString
          Try(DataFeedItemContent(Some(contentText), None, None, None))
        }
      } yield DataFeedItem(
        "twitter",
        (tailContent.getOrElse(content) \ "lastUpdated").as[DateTime],
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
        compareString(content, tailContent.get, "name", "Name", Some("user")),
        compareString(
          content,
          tailContent.get,
          "location",
          "Location",
          Some("user")
        ),
        compareString(
          content,
          tailContent.get,
          "description",
          "Description",
          Some("user")
        ),
        compareInt(
          content,
          tailContent.get,
          "friends_count",
          "Number of Friends",
          Some("user")
        ),
        compareInt(
          content,
          tailContent.get,
          "followers_count",
          "Number of Followers",
          Some("user")
        ),
        compareInt(
          content,
          tailContent.get,
          "favourites_count",
          "Number of Favorites",
          Some("user")
        ),
        compareInt(
          content,
          tailContent.get,
          "profile_image_url_https",
          "Profile Image",
          Some("user")
        ),
        compareInt(
          content,
          tailContent.get,
          "statuses_count",
          "Number of Tweets",
          Some("user")
        )
      )
}

class TwitterFeedMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "twitter/tweets",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("lastUpdated", None, f))),
            None
          )
        ),
        Some("lastUpdated"),
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
      title <-
        Try(
          if ((content \ "retweeted").as[Boolean])
            DataFeedItemTitle("You retweeted", None, Some("repeat"))
          else if ((content \ "in_reply_to_user_id").isDefined && !((content \ "in_reply_to_user_id").get == JsNull))
            DataFeedItemTitle(
              s"You replied to @${(content \ "in_reply_to_screen_name").as[String]}",
              None,
              None
            )
          else
            DataFeedItemTitle("You tweeted", None, None)
        )
      itemContent <- Try(
                       DataFeedItemContent((content \ "text").asOpt[String], None, None, None)
                     )
      date <- Try((content \ "lastUpdated").as[DateTime])
    } yield {
      val location = Try(
        DataFeedItemLocation(
          geo = (content \ "coordinates")
            .asOpt[JsObject]
            .map(coordinates =>
              LocationGeo(
                (coordinates \ "coordinates" \ 0).as[Double],
                (coordinates \ "coordinates" \ 1).as[Double]
              )
            ),
          address = (content \ "place")
            .asOpt[JsObject]
            .map(address =>
              LocationAddress(
                (address \ "country").asOpt[String],
                (address \ "name").asOpt[String],
                None,
                None,
                None
              )
            ),
          tags = None
        )
      ).toOption
        .filter(l => l.address.isDefined || l.geo.isDefined || l.tags.isDefined)

      DataFeedItem(
        "twitter",
        date,
        Seq("post"),
        Some(title),
        Some(itemContent),
        location
      )
    }
}

class TwitterProfileStaticDataMapper extends StaticDataEndpointMapper {
  def dataQueries(): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(EndpointQuery("twitter/tweets", None, None, None)),
        Some("id"),
        Some("descending"),
        Some(1)
      )
    )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      endpoint: String): Seq[StaticDataValues] = {
    val maybeUserData            = (content \ "user").asOpt[Map[String, JsValue]]
    val lastPartOfEndpointString = endpoint.split("/").last
    maybeUserData match {
      case Some(user) =>
        Seq(
          StaticDataValues(
            lastPartOfEndpointString,
            user.filterKeys(key => key != "entities")
          )
        )
      case _ => Seq()
    }
  }
}
