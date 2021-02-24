package org.hatdex.hat.she.mappers

import java.util.UUID

import scala.util.{ Failure, Try }

import io.dataswift.models.hat.applications.{ DataFeedItem, DataFeedItemContent, DataFeedItemTitle }
import io.dataswift.models.hat.{ EndpointQuery, EndpointQueryFilter, PropertyQuery }
import org.hatdex.hat.she.models.StaticDataValues
import org.joda.time.DateTime
import org.joda.time.format.{ DateTimeFormat, DateTimeFormatter }
import play.api.libs.json.{ JsError, JsString, JsSuccess, JsValue, Reads }

class FitbitWeightMapper extends DataEndpointMapper {
  override val dateTimeFormat: DateTimeFormatter =
    DateTimeFormat.forPattern("yyyy-MM-dd")

  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "fitbit/weight",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("date", None, f))),
            None
          )
        ),
        Some("date"),
        Some("descending"),
        None
      )
    )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] = {
    val title = DataFeedItemTitle(
      "You added a new weight measurement",
      None,
      Some("weight")
    )

    val itemContent = DataFeedItemContent(
      Some(
        Seq(
          (content \ "weight").asOpt[Double].map(w => s"- Weight: $w"),
          (content \ "fat").asOpt[Double].map(w => s"- Body Fat: $w"),
          (content \ "bmi").asOpt[Double].map(w => s"- BMI: $w")
        ).flatten.mkString("\n")
      ),
      None,
      None,
      None
    )

    for {
      date <- Try(
                JsString(
                  s"${(content \ "date").as[String]}T${(content \ "time").as[String]}"
                ).as[DateTime]
              )
    } yield DataFeedItem(
      "fitbit",
      date,
      Seq("fitness", "weight"),
      Some(title),
      Some(itemContent),
      None
    )
  }
}

class FitbitActivityMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "fitbit/activity",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("originalStartTime", None, f))),
            None
          )
        ),
        Some("originalStartTime"),
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
      date <- Try((content \ "originalStartTime").as[DateTime])
    } yield {
      val title =
        DataFeedItemTitle("You logged Fitbit activity", None, Some("fitness"))

      val message = Seq(
        (content \ "activityName").asOpt[String].map(c => s"- Activity: $c"),
        (content \ "duration")
          .asOpt[Long]
          .map(c => s"- Duration: ${c / 1000 / 60} minutes"),
        (content \ "averageHeartRate")
          .asOpt[Long]
          .map(c => s"- Average heart rate: $c"),
        (content \ "calories").asOpt[Long].map(c => s"- Calories burned: $c")
      ).flatten.mkString("\n")

      DataFeedItem(
        "fitbit",
        date,
        Seq("fitness", "activity"),
        Some(title),
        Some(DataFeedItemContent(Some(message), None, None, None)),
        None
      )
    }
}

class FitbitActivityDaySummaryMapper extends DataEndpointMapper {
  override val dateTimeFormat: DateTimeFormatter =
    DateTimeFormat.forPattern("yyyy-MM-dd")
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "fitbit/activity/day/summary",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("dateCreated", None, f))),
            None
          )
        ),
        Some("dateCreated"),
        Some("descending"),
        None
      )
    )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] = {
    val fitbitSummary = for {
      count <- Try((content \ "steps").as[Int]) if count > 0
      date <- Try((content \ "dateCreated").as[DateTime])
    } yield {
      val adjustedDate =
        if (date.getSecondOfDay == 0)
          date.secondOfDay().withMaximumValue()
        else
          date
      val title =
        DataFeedItemTitle(s"You walked $count steps", None, Some("fitness"))
      DataFeedItem(
        "fitbit",
        adjustedDate,
        Seq("fitness", "activity"),
        Some(title),
        None,
        None
      )
    }

    fitbitSummary recoverWith {
      case _: NoSuchElementException =>
        Failure(new RuntimeException("Fitbit empty day summary"))
    }
  }
}

class FitbitSleepMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "fitbit/sleep",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("endTime", None, f))),
            None
          )
        ),
        Some("endTime"),
        Some("descending"),
        None
      )
    )

  def fitbitDateCorrector(date: String): String = {
    val zonedDatePattern =
      """.*(z|Z|\+\d{2})(:?\d{2})?$""".r // does the string end with ISO8601 timezone indicator
    if (zonedDatePattern.findFirstIn(date).isDefined)
      date
    else
      date + "+0000"
  }

  implicit override val DefaultJodaDateTimeReads: Reads[DateTime] =
    jodaDateReads("", fitbitDateCorrector)

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] = {
    val title = DataFeedItemTitle("You woke up!", None, Some("sleep"))

    val timeInBed = (content \ "timeInBed")
      .asOpt[Int]
      .map(t => s"You spent ${t / 60} hours and ${t % 60} minutes in bed.")
    val minutesAsleep = (content \ "minutesAsleep")
      .asOpt[Int]
      .map(asleep =>
        s"You slept for ${asleep / 60} hours and ${asleep % 60} minutes" +
            (content \ "minutesAwake")
              .asOpt[Int]
              .map(t => s" and were awake for $t minutes")
              .getOrElse("") +
            "."
      )
    val efficiency = (content \ "efficiency")
      .asOpt[Int]
      .map(e => s"Your sleep efficiency score tonight was $e.")

    val itemContent = DataFeedItemContent(
      Some(Seq(timeInBed, minutesAsleep, efficiency).flatten.mkString(" ")),
      None,
      None,
      None
    )

    for {
      date <- Try((content \ "endTime").as[DateTime])
    } yield DataFeedItem(
      "fitbit",
      date,
      Seq("fitness", "sleep"),
      Some(title),
      Some(itemContent),
      None
    )
  }
}

class FitbitProfileMapper extends DataEndpointMapper with FeedItemComparator {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "fitbit/profile",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("dateCreated", None, f))),
            None
          )
        ),
        Some("dateCreated"),
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
                   DataFeedItemTitle("Your Fitbit Data has changed.", None, None)
                 )
        itemContent <- {
          val contentText = comparison.map(item => s"${item._2}\n").mkString
          Try(DataFeedItemContent(Some(contentText), None, None, None))
        }
      } yield DataFeedItem(
        "fitbit",
        (tailContent.getOrElse(content) \ "dateCreated").as[DateTime],
        Seq("profile"),
        Some(title),
        Some(itemContent),
        None
      )
  }

  /**
    * @param content
    * @param tailContent
    * @return (true if data is the same and both content is the not None, )
    */
  def compare(
      content: JsValue,
      tailContent: Option[JsValue]): Seq[(Boolean, String)] =
    if (tailContent.isEmpty)
      Seq()
    else
      // Note: we are comparing in descending order. Reverse content <-> tailContent if ascending
      Seq(
        compareString(tailContent.get, content, "fullName", "Name"),
        compareString(tailContent.get, content, "displayName", "Display Name"),
        compareString(tailContent.get, content, "gender", "Gender"),
        compareInt(tailContent.get, content, "age", "Age"),
        compareInt(tailContent.get, content, "height", "Height"),
        compareFloat(tailContent.get, content, "weight", "Weight"),
        compareString(tailContent.get, content, "country", "Country"),
        // TODO: Terry: I don't understand the discrepancy. Monitor
        // compareString(tailContent.get, content, "timezone", "Time Zone"))
        compareString(content, tailContent.get, "timezone", "Time Zone")
      )
}

class FitbitProfileStaticDataMapper extends StaticDataEndpointMapper {
  def dataQueries(): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(EndpointQuery("fitbit/profile", None, None, None)),
        Some("hat_updated_time"),
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

        Seq(
          StaticDataValues(
            lastPartOfEndpointString,
            value.filterKeys(key => key != "features" && key != "topBadges")
          )
        )
      case e: JsError =>
        logger.error(s"Couldn't validate static data JSON for $endpoint. $e")
        Seq()
    }
  }
}
