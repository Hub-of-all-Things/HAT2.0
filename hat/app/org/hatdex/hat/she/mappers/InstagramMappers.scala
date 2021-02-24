package org.hatdex.hat.she.mappers

import java.util.UUID

import scala.util.Try

import io.dataswift.models.hat.applications.{
  DataFeedItem,
  DataFeedItemContent,
  DataFeedItemLocation,
  DataFeedItemMedia,
  DataFeedItemTitle,
  LocationAddress,
  LocationGeo
}
import io.dataswift.models.hat.{ EndpointQuery, EndpointQueryFilter, FilterOperator, PropertyQuery }
import org.hatdex.hat.she.models.StaticDataValues
import org.joda.time.DateTime
import play.api.libs.json.{ __, JsError, JsNumber, JsObject, JsResult, JsSuccess, JsValue, Json }

class InstagramMediaMapper extends DataEndpointMapper {
  override protected val dataDeduplicationField: Option[String] = Some("id")
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] = {
    val unixDateFilter = fromDate.flatMap { _ =>
      Some(
        FilterOperator.Between(
          Json.toJson(fromDate.map(t => (t.getMillis / 1000).toString)),
          Json.toJson(untilDate.map(t => (t.getMillis / 1000).toString))
        )
      )
    }

    val propertyQueryv1 = PropertyQuery(
      List(
        EndpointQuery(
          "instagram/feed",
          None,
          unixDateFilter.map(f => Seq(EndpointQueryFilter("created_time", None, f))),
          None
        )
      ),
      Some("created_time"),
      Some("descending"),
      None
    )

    val propertyQueryv2 = PropertyQuery(
      List(
        EndpointQuery(
          "instagram/feed",
          None,
          unixDateFilter.map(f => Seq(EndpointQueryFilter("ds_created_time", None, f))),
          None
        )
      ),
      Some("ds_created_time"),
      Some("descending"),
      None
    )

    Seq(propertyQueryv2, propertyQueryv1) //ordering is on purpose
  }

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] =
    (content \ "ds_api_version").asOpt[String] match {
      case Some(_) => instagramApiv2(content)
      case None    => instagramApiv1(content)
    }

  private def instagramApiv1(content: JsValue): Try[DataFeedItem] =
    for {
      createdTime <- Try(
                       new DateTime((content \ "created_time").as[String].toLong * 1000)
                     )
      tags <- Try((content \ "tags").as[List[String]])
      kind <- Try((content \ "type").as[String])
      title <- Try(Some(DataFeedItemTitle("You posted", None, Some(kind))))
      feedItemContent <- Try(
                           Some(
                             DataFeedItemContent(
                               (content \ "caption" \ "text").asOpt[String],
                               None,
                               kind match {
                                 case "image" =>
                                   Some(
                                     Seq(
                                       DataFeedItemMedia(
                                         (content \ "images" \ "thumbnail" \ "url").asOpt[String],
                                         (content \ "images" \ "standard_resolution" \ "url")
                                           .asOpt[String]
                                       )
                                     )
                                   )
                                 case "carousel" =>
                                   Some((content \ "carousel_media").as[Seq[JsObject]].map { imageInfo =>
                                     DataFeedItemMedia(
                                       (imageInfo \ "images" \ "thumbnail" \ "url")
                                         .asOpt[String],
                                       (imageInfo \ "images" \ "standard_resolution" \ "url")
                                         .asOpt[String]
                                     )
                                   })
                                 case _ => None
                               },
                               None
                             )
                           )
                         )
    } yield {
      val location = Try(
        DataFeedItemLocation(
          geo = (content \ "location")
            .asOpt[JsObject]
            .map(location =>
              LocationGeo(
                (location \ "longitude").as[Double],
                (location \ "latitude").as[Double]
              )
            ),
          address = (content \ "location" \ "street_address")
            .asOpt[String]
            .map(fullAddress => LocationAddress(None, None, Some(fullAddress), None, None)),
          tags = None
        )
      ).toOption

      DataFeedItem(
        "instagram",
        createdTime,
        tags,
        title,
        feedItemContent,
        location
      )
    }

  private def instagramApiv2(content: JsValue): Try[DataFeedItem] =
    for {
      createdTime <- Try(
                       new DateTime((content \ "ds_created_time").as[String].toLong * 1000)
                     )
      description <- Try((content \ "caption").as[String])
      kind <- Try((content \ "media_type").as[String])
      title <- Try(
                 Some(DataFeedItemTitle("You posted", None, Some(kind.toLowerCase)))
               )
      feedItemContent <- Try(
                           Some(
                             DataFeedItemContent(
                               Some(description),
                               None,
                               kind match {
                                 case "IMAGE" =>
                                   Some(
                                     Seq(
                                       DataFeedItemMedia(
                                         (content \ "media_url").asOpt[String],
                                         (content \ "media_url").asOpt[String]
                                       )
                                     )
                                   )
                                 case _ => None
                               },
                               None
                             )
                           )
                         )
    } yield {
      val regex = "#\\w+".r
      val tags  = regex.findAllIn(description).toList
      logger.debug(s"Tags: $tags")
      DataFeedItem("instagram", createdTime, tags, title, feedItemContent, None)
    }
}

class InstagramProfileStaticDataMapper extends StaticDataEndpointMapper {
  def dataQueries(): Seq[PropertyQuery] = {
    val propertyQueryv1 = PropertyQuery(
      List(EndpointQuery("instagram/profile", None, None, None)),
      Some("hat_created_time"),
      Some("descending"),
      Some(1)
    )
    val propertyQueryv2 = PropertyQuery(
      List(EndpointQuery("instagram/profile", None, None, None)),
      Some("ds_created_time"),
      Some("descending"),
      Some(1)
    )

    Seq(propertyQueryv2, propertyQueryv1) //ordering is on purpose
  }

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      endpoint: String): Seq[StaticDataValues] = {
    val eventualData = content.validate[JsObject]
    eventualData match {
      case JsSuccess(value, _) =>
        val lastPartOfEndpointString = endpoint.split("/").last
        (value \ "ds_api_version").asOpt[String] match {
          case Some(_) => instagramApiv2(lastPartOfEndpointString, value)
          case None    => instagramApiv1(lastPartOfEndpointString, value)
        }

      case e: JsError =>
        logger.error(s"Couldn't validate static data JSON for $endpoint. $e")
        Seq()
    }
  }

  private def instagramApiv1(
      lastPartOfEndpointString: String,
      value: JsObject): Seq[StaticDataValues] = {
    val maybeTransformedData = transformInstagramv1(value).flatMap(item => item.validate[Map[String, JsValue]])
    maybeTransformedData match {
      case JsSuccess(data, _) =>
        Seq(StaticDataValues(lastPartOfEndpointString, data - "counts"))

      case e: JsError =>
        logger.error(
          s"Couldn't validate static data JSON for $lastPartOfEndpointString. $e"
        )
        Seq()
    }
  }

  private def transformInstagramv1(rawData: JsObject): JsResult[JsValue] = {
    val transformation = __.json.update(
      __.read[JsObject]
        .map { profile =>
          logger.info(s"Trying to map profile: $profile")
          val totalImagesUploaded = (profile \ "counts" \ "media")
            .asOpt[JsNumber]
            .getOrElse(JsNumber(0))
          val totalFollowers = (profile \ "counts" \ "followed_by")
            .asOpt[JsNumber]
            .getOrElse(JsNumber(0))
          val totalPeopleUsersFollows = (profile \ "counts" \ "follows")
            .asOpt[JsNumber]
            .getOrElse(JsNumber(0))

          profile ++ JsObject(
            Map(
              "media" -> totalImagesUploaded,
              "follows" -> totalPeopleUsersFollows,
              "followers" -> totalFollowers
            )
          )
        }
    )

    rawData.transform(transformation)
  }

  private def instagramApiv2(
      lastPartOfEndpointString: String,
      value: JsObject): Seq[StaticDataValues] = {
    val maybeData = value.validate[Map[String, JsValue]]
    maybeData match {
      case JsSuccess(data, _) =>
        Seq(StaticDataValues(lastPartOfEndpointString, data))

      case e: JsError =>
        logger.error(
          s"Couldn't validate static data JSON for $lastPartOfEndpointString. $e"
        )
        Seq()
    }
  }
}
