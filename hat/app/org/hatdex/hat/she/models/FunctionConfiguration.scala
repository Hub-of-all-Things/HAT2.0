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
 * 11 / 2017
 */

package org.hatdex.hat.she.models

import java.util.UUID

import io.dataswift.models.hat.json.{ ApplicationJsonProtocol, DataFeedItemJsonProtocol, RichDataJsonFormats }
import io.dataswift.models.hat.applications._
import io.dataswift.models.hat.{ EndpointData, EndpointDataBundle, FormattedText }
import org.hatdex.hat.dal.ModelTranslation
import org.hatdex.hat.dal.Tables.{ DataBundlesRow, SheFunctionRow, SheFunctionStatusRow }
import org.joda.time.{ DateTime, Period }
import play.api.libs.json._

case class Response(
    namespace: String,
    endpoint: String,
    data: Seq[JsValue],
    linkedRecords: Seq[UUID])

case class Request(
    data: Map[String, Seq[EndpointData]],
    linkRecords: Boolean)

case class FunctionInfo(
    version: Version,
    versionReleaseDate: DateTime,
    updateNotes: Option[ApplicationUpdateNotes],
    name: String,
    headline: String,
    description: FormattedText,
    termsUrl: String,
    supportContact: String,
    dataPreview: Option[Seq[DataFeedItem]],
    graphics: ApplicationGraphics,
    dataPreviewEndpoint: Option[String])

case class FunctionStatus(
    available: Boolean,
    enabled: Boolean,
    lastExecution: Option[DateTime],
    executionStarted: Option[DateTime])

case class FunctionConfiguration(
    id: String,
    info: FunctionInfo,
    developer: ApplicationDeveloper,
    trigger: FunctionTrigger.Trigger,
    dataBundle: EndpointDataBundle,
    status: FunctionStatus) {
  def update(other: FunctionConfiguration): FunctionConfiguration =
    FunctionConfiguration(
      this.id,
      other.info,
      other.developer,
      other.trigger,
      other.dataBundle,
      this.status.copy(
        other.status.available,
        this.status.enabled || other.status.enabled,
        this.status.lastExecution.orElse(other.status.lastExecution),
        this.status.executionStarted.orElse(other.status.executionStarted)
      )
    )
}

object FunctionConfiguration {
  def apply(
      function: SheFunctionRow,
      functionStatus: Option[SheFunctionStatusRow],
      bundle: DataBundlesRow,
      available: Boolean = false): FunctionConfiguration = {
    import DataFeedItemJsonProtocol.feedItemFormat
    import org.hatdex.hat.she.models.FunctionConfigurationJsonProtocol._
    import org.hatdex.hat.she.models.FunctionTrigger.Trigger
    import ApplicationJsonProtocol.formattedTextFormat
    import ApplicationJsonProtocol.applicationGraphicsFormat

    FunctionConfiguration(
      function.id,
      FunctionInfo(
        Version(function.version),
        function.versionReleaseDate,
        None,
        function.name,
        function.headline,
        function.description.as[FormattedText],
        function.termsUrl,
        function.developerSupportEmail,
        function.dataPreview.map(_.as[Seq[DataFeedItem]]),
        function.graphics.as[ApplicationGraphics],
        function.dataPreviewEndpoint
      ),
      ApplicationDeveloper(
        function.developerId,
        function.developerName,
        function.developerUrl,
        function.developerCountry,
        None
      ),
      function.trigger.as[Trigger],
      ModelTranslation.fromDbModel(bundle),
      FunctionStatus(
        available,
        functionStatus.exists(_.enabled),
        functionStatus.flatMap(_.lastExecution),
        functionStatus.flatMap(_.executionStarted)
      )
    )

  }
}

object FunctionTrigger {
  // Sealed type for the different types of function triggers available
  sealed trait Trigger {
    val triggerType: String
  }

  case class TriggerPeriodic(period: Period) extends Trigger {
    final val triggerType: String = "periodic"
  }

  case class TriggerIndividual() extends Trigger {
    final val triggerType: String = "individual"
  }

  case class TriggerManual() extends Trigger {
    final val triggerType: String = "manual"
  }

}

trait FunctionConfigurationJsonProtocol
    extends JodaWrites
    with JodaReads
    with RichDataJsonFormats
    with DataFeedItemJsonProtocol {
  import FunctionTrigger._
  import ApplicationJsonProtocol.applicationDeveloperFormat
  import ApplicationJsonProtocol.applicationGraphicsFormat
  import ApplicationJsonProtocol.versionFormat
  import ApplicationJsonProtocol.applicationUpdateNotesFormat
  import ApplicationJsonProtocol.formattedTextFormat

  implicit protected val triggerPeriodicFormat: Format[TriggerPeriodic] =
    Json.format[TriggerPeriodic]

  implicit val triggerFormat: Format[Trigger] = new Format[Trigger] {
    def reads(json: JsValue): JsResult[Trigger] =
      (json \ "triggerType").as[String] match {
        case "periodic" =>
          Json.fromJson[TriggerPeriodic](json)(triggerPeriodicFormat)
        case "individual" => JsSuccess(TriggerIndividual())
        case "manual"     => JsSuccess(TriggerManual())
        case triggerType =>
          JsError(s"Unexpected JSON value $triggerType in $json")
      }

    def writes(trigger: Trigger): JsValue = {
      val triggerJson = trigger match {
        case ds: TriggerPeriodic  => Json.toJson(ds)(triggerPeriodicFormat)
        case _: TriggerIndividual => JsObject(Seq())
        case _: TriggerManual     => JsObject(Seq())
      }
      triggerJson
        .as[JsObject]
        .+(("triggerType", Json.toJson(trigger.triggerType)))
    }
  }

  implicit val functionInfoFormat: Format[FunctionInfo] =
    Json.format[FunctionInfo]
  implicit val functionStatusFormat: Format[FunctionStatus] =
    Json.format[FunctionStatus]
  implicit val functionConfigurationFormat: Format[FunctionConfiguration] =
    Json.format[FunctionConfiguration]
  implicit val responseFormat: Format[Response] = Json.format[Response]
  implicit val requestFormat: Format[Request]   = Json.format[Request]
}

object FunctionConfigurationJsonProtocol extends FunctionConfigurationJsonProtocol
