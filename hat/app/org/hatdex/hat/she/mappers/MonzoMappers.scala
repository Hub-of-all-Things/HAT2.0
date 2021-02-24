package org.hatdex.hat.she.mappers

import java.util.UUID

import scala.util.Try

import io.dataswift.models.hat.applications.{
  DataFeedItem,
  DataFeedItemContent,
  DataFeedItemLocation,
  DataFeedItemTitle,
  LocationAddress,
  LocationGeo
}
import io.dataswift.models.hat.{ EndpointQuery, EndpointQueryFilter, PropertyQuery }
import org.joda.time.DateTime
import play.api.libs.json.JsValue

class MonzoTransactionMapper extends DataEndpointMapper {
  def dataQueries(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Seq[PropertyQuery] =
    Seq(
      PropertyQuery(
        List(
          EndpointQuery(
            "monzo/transactions",
            None,
            dateFilter(fromDate, untilDate).map(f => Seq(EndpointQueryFilter("created", None, f))),
            None
          )
        ),
        Some("created"),
        Some("descending"),
        None
      )
    )

  private val currencyMap = Map(
    "EUR" -> "\u20AC",
    "GBP" -> "\u00A3",
    "USD" -> "\u0024",
    "JPY" -> "\u00A5",
    "THB" -> "\u0E3F"
  )

  def mapDataRecord(
      recordId: UUID,
      content: JsValue,
      tailRecordId: Option[UUID] = None,
      tailContent: Option[JsValue] = None): Try[DataFeedItem] = {
    for {
      paymentAmount <- Try((content \ "local_amount").as[Int] / 100.0)
      paymentCurrency <- Try {
                           val currencyCode = (content \ "local_currency").as[String]
                           currencyMap.getOrElse(currencyCode, currencyCode)
                         }
      title <- Try(
                 if (
                   (content \ "is_load")
                     .as[Boolean] && (content \ "metadata" \ "p2p_transfer_id")
                     .asOpt[String]
                     .isEmpty
                 )
                   DataFeedItemTitle(
                     "You topped up",
                     Some(s"$paymentCurrency$paymentAmount"),
                     Some("money")
                   )
                 else if ((content \ "metadata" \ "p2p_transfer_id").asOpt[String].nonEmpty)
                   if ((content \ "originator").as[Boolean])
                     DataFeedItemTitle(
                       "You paid a friend",
                       Some(s"$paymentCurrency${-paymentAmount}"),
                       Some("money")
                     )
                   else
                     DataFeedItemTitle(
                       "You received money from a friend",
                       Some(s"$paymentCurrency$paymentAmount"),
                       Some("money")
                     )
                 else if (
                   (content \ "metadata" \ "is_reversal")
                     .asOpt[String]
                     .contains("true")
                 )
                   DataFeedItemTitle(
                     "Your payment was refunded",
                     Some(s"$paymentCurrency$paymentAmount"),
                     Some("money")
                   )
                 else if (paymentAmount > 0)
                   DataFeedItemTitle(
                     "You received",
                     Some(s"$paymentCurrency$paymentAmount"),
                     Some("money")
                   )
                 else
                   DataFeedItemTitle(
                     "You spent",
                     Some(s"$paymentCurrency${-paymentAmount}"),
                     Some("money")
                   )
               )
      itemContent <- Try(
                       DataFeedItemContent(
                         Option(s"""|${(content \ "counterparty" \ "name")
                           .asOpt[String]
                           .orElse((content \ "merchant" \ "name").asOpt[String])
                           .getOrElse("")}
              |
             |${(content \ "notes").asOpt[String].getOrElse("")}
              |
             |${(content \ "description").asOpt[String].getOrElse("")}
              |
             |${(content \ "merchant" \ "address" \ "short_formatted")
                           .asOpt[String]
                           .getOrElse("")}""".stripMargin.replaceAll("\n\n\n", "").trim)
                           .filter(_.nonEmpty),
                         None,
                         None,
                         None
                       )
                     )
      date <- Try((content \ "created").as[DateTime])
      tags <- Try(Seq("transaction", (content \ "category").as[String]))
    } yield {

      val locationGeo = Try(
        LocationGeo(
          (content \ "merchant" \ "address" \ "longitude").as[Double],
          (content \ "merchant" \ "address" \ "latitude").as[Double]
        )
      ).toOption

      val locationAddress = Try(
        LocationAddress(
          (content \ "merchant" \ "address" \ "country").asOpt[String],
          (content \ "merchant" \ "address" \ "city").asOpt[String],
          (content \ "merchant" \ "name").asOpt[String],
          (content \ "merchant" \ "address" \ "address").asOpt[String],
          (content \ "merchant" \ "address" \ "postcode").asOpt[String]
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
      val feedItemContent =
        if (itemContent == DataFeedItemContent(None, None, None, None))
          None
        else
          Some(itemContent)

      DataFeedItem("monzo", date, tags, Some(title), feedItemContent, location)
    }
  }
}
