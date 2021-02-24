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

package org.hatdex.hat.she.service

import scala.concurrent.{ ExecutionContext, Future }

import com.google.inject.{ AbstractModule, Provides }
import net.codingwell.scalaguice.ScalaModule
import org.hatdex.hat.api.HATTestContext
import io.dataswift.models.hat._
import io.dataswift.models.hat.applications._
import org.hatdex.hat.resourceManagement.FakeHatConfiguration
import org.hatdex.hat.she.models._
import org.joda.time.DateTime
import play.api.{ Application }
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.json.{ JsBoolean, JsObject }

trait FunctionServiceContext extends HATTestContext {

  /**
   * A fake Guice module.
   */
  class CustomisedFakeModule extends AbstractModule with ScalaModule {

    @Provides
    def provideFunctionExecutableRegistry(): FunctionExecutableRegistry = {
      new FunctionExecutableRegistry(Seq(registeredFunction, registeredDummyFunction, registeredDummyFunctionAvailable))
    }
  }

  override lazy val application: Application = new GuiceApplicationBuilder()
    .configure(FakeHatConfiguration.config)
    .overrides(new FakeModule)
    .overrides(new ExtrasModule)
    .overrides(new CustomisedFakeModule)
    .build()

  val dummyFunctionConfiguration = FunctionConfiguration(
    "test-dummy-function",
    FunctionInfo(
      Version("1.0.0"),
      DateTime.now(),
      None,
      "test-dummy-function",
      "Dummy Function",
      FormattedText(text = "Dummy Function", None, None),
      "terms",
      "contact@email.com",
      None,
      ApplicationGraphics(
        Drawable(None, "", None, None),
        Drawable(None, "", None, None),
        Seq(Drawable(None, "", None, None))),
      None),
    ApplicationDeveloper("hatdex", "HATDeX", "https://hatdex.org", Some("United Kingdom"), None),
    FunctionTrigger.TriggerIndividual(),
    dataBundle = EndpointDataBundle("test-data-feed-dummy-mapper", Map()),
    status = FunctionStatus(available = false, enabled = false, lastExecution = None, executionStarted = None))

  val dummyFunctionConfigurationAvailable = dummyFunctionConfiguration.copy(
    id = "test-dummy-function-available",
    info = dummyFunctionConfiguration.info.copy(name = "test-dummy-function-available"),
    dataBundle = EndpointDataBundle("test-data-feed-dummy-mapper-vailable", Map()),
    status = dummyFunctionConfiguration.status.copy(available = true))

  val dummyFunctionConfigurationUpdated = dummyFunctionConfiguration.copy(
    id = "test-dummy-function",
    info = dummyFunctionConfiguration.info.copy(name = "test-dummy-function", headline = "Updated Function"),
    dataBundle = EndpointDataBundle("test-data-feed-dummy-mapper", Map()),
    status = dummyFunctionConfiguration.status.copy(available = false, enabled = true))

  //  FunctionConfiguration("test-dummy-function", "test-dummy-function", "Updated Function", "Dummy Function", None,
  //    FunctionTrigger.TriggerIndividual(), available = false, enabled = true,
  //    dataBundle = EndpointDataBundle("test-data-feed-dummy-mapper", Map()),
  //    None, None, None)

  val unavailableFunctionConfiguration = dummyFunctionConfiguration.copy(
    id = "test-test-unavailable-function",
    info = dummyFunctionConfiguration.info.copy(name = "test-test-unavailable-function", headline = "Unavailable Function"),
    dataBundle = EndpointDataBundle("test-unavailable-function-bundler", Map()),
    status = dummyFunctionConfiguration.status.copy(available = false, enabled = false))

  //  val unavailableFunctionConfiguration = FunctionConfiguration("test-test-unavailable-function", "test-test-unavailable-function", "Unavailable Function", "Dummy Function", None,
  //    FunctionTrigger.TriggerIndividual(), available = false, enabled = false,
  //    dataBundle = EndpointDataBundle("test-unavailable-function-bundler", Map()),
  //    None, None, None)

  val registeredFunction = new FunctionExecutable {
    val configuration: FunctionConfiguration = dummyFunctionConfiguration.copy(
      id = "data-feed-direct-mapper",
      info = dummyFunctionConfiguration.info.copy(name = "data-feed-direct-mapper", headline = "Dummy Function"),
      dataBundle = EndpointDataBundle(
        "data-feed-counter",
        Map(
          "facebook/feed" -> PropertyQuery(
            List(
              EndpointQuery("facebook/feed", None, None, None)),
            Some("created_time"), Some("descending"), None),
          "facebook/events" -> PropertyQuery(
            List(
              EndpointQuery("facebook/events", None, None, None)),
            Some("start_time"), Some("descending"), None),
          "twitter/tweets" -> PropertyQuery(
            List(
              EndpointQuery("twitter/tweets", None, None, None)),
            Some("lastUpdated"), Some("descending"), None),
          "fitbit/sleep" -> PropertyQuery(
            List(
              EndpointQuery("fitbit/sleep", None,
                None, None)),
            Some("endTime"), Some("descending"), None),
          "fitbit/activity" -> PropertyQuery(
            List(
              EndpointQuery("fitbit/activity", None,
                None, None)),
            Some("originalStartTime"), Some("descending"), None),
          "fitbit/weight" -> PropertyQuery(
            List(
              EndpointQuery("fitbit/weight", None,
                None, None)),
            Some("date"), Some("descending"), None),
          "calendar/google/events" -> PropertyQuery(
            List(
              EndpointQuery("calendar/google/events", None, None, None)),
            Some("start.dateTime"), Some("descending"), None),
          "notables/feed" -> PropertyQuery(
            List(
              EndpointQuery("rumpel/notablesv1", None, None, None)),
            Some("created_time"), Some("descending"), None),
          "spotify/feed" -> PropertyQuery(
            List(
              EndpointQuery("spotify/feed", None, None, None)),
            Some("played_at"), Some("descending"), None),
          "monzo/transactions" -> PropertyQuery(
            List(
              EndpointQuery("monzo/transactions", None, None, None)),
            Some("created"), Some("descending"), None))),
      status = dummyFunctionConfiguration.status.copy(available = true, enabled = false))

    val namespace = "test"
    val endpoint = "test-endpoint"

    implicit val ec: ExecutionContext = ExecutionContext.Implicits.global
    def execute(configuration: FunctionConfiguration, request: Request): Future[Seq[Response]] = {
      Future.successful(
        request.data.values.flatten
          .map(d => Response(namespace, endpoint, Seq(d.data.as[JsObject].+("mapped" -> JsBoolean(true))), Seq())).toSeq)
    }
    override def bundleFilterByDate(fromDate: Option[DateTime], untilDate: Option[DateTime]): Future[EndpointDataBundle] = {
      // Explicitly ignore the parameters - compiler complains about unused parameters
      (fromDate, untilDate)
      Future.successful(configuration.dataBundle)
    }
  }

  val registeredDummyFunction: FunctionExecutable = new DummyFunctionExecutable(dummyFunctionConfiguration)
  val registeredDummyFunctionAvailable: FunctionExecutable = new DummyFunctionExecutable(dummyFunctionConfigurationAvailable)
}

class DummyFunctionExecutable(conf: FunctionConfiguration) extends FunctionExecutable {
  val configuration = conf

  val namespace = "test"
  val endpoint = "test-endpoint"

  implicit val ec: ExecutionContext = ExecutionContext.Implicits.global

  override def execute(configuration: FunctionConfiguration, request: Request): Future[Seq[Response]] = {
    Future.failed(new RuntimeException("Dummy Function"))
  }
}
