// This is set as it is to access the private members of the filters to test them.
package com.github.stijndehaes.playprometheusfilters.filters

/* Test cases based on the archived project: https://github.com/stijndehaes/play-prometheus-filters */

import javax.inject.Inject

import scala.concurrent.ExecutionContextExecutor

import akka.actor.ActorSystem
import akka.stream.ActorMaterializer
import io.dataswift.test.common.BaseSpec
import io.prometheus.client.CollectorRegistry
import play.api.libs.typedmap.TypedMap
import play.api.mvc._
import play.api.routing.{HandlerDef, Router}
import play.api.test.Helpers._
import play.api.test._

class PrometheusFiltersSpec extends BaseSpec {

  implicit val ec: ExecutionContextExecutor = scala.concurrent.ExecutionContext.global
  implicit val system: ActorSystem          = ActorSystem()
  implicit val materializer                 = ActorMaterializer()

  "LatencyFilter" should "Measure the latency" in {
    // I needed to have an independnt collector per test, otherwise they complain about having duplicate labels.
    val registryOne = new CollectorRegistry(true)
    val promFilter  = new LatencyFilter(registryOne)
    val fakeRequest = FakeRequest()
    val action      = new MockController(stubControllerComponents()).ok

    await(promFilter(action)(fakeRequest).run())

    //val metrics = promFilter.metrics(0).metric.collect()
    val metrics = promFilter.requestLatency.collect()
    metrics must have size 1
    val samples     = metrics.get(0).samples
    val countSample = samples.get(samples.size() - 2)
    countSample.value mustBe 1.0
    countSample.labelValues must have size 0
  }

  "StatusAndRouteLatencyFilter" should "Measure the latency and status" in {
    val expectedLabelCount: Long = 6
    val expectedMethod           = "test"
    val expectedStatus: String   = "200"
    val expectedControllerName   = "promController"
    val expectedPath             = "/path"
    val expectedVerb             = "GET"
    val expectedLatencyBucket    = "0.005"

    // I needed to have an independnt collector per test, otherwise they complain about having duplicate labels.
    val registryTwo = new CollectorRegistry(true)
    val promFilter  = new StatusAndRouteLatencyFilter(registryTwo)
    val fakeRequest = FakeRequest().withAttrs(
      TypedMap(
        Router.Attrs.HandlerDef -> HandlerDef(null, null, "promController", "test", null, "GET", "/path", null, null)
      )
    )

    val action =
      new MockController(stubControllerComponents()).ok

    await(promFilter(action)(fakeRequest).run())

    val metrics = promFilter.requestLatency.collect()
    metrics must have size 1
    val samples = metrics.get(0).samples

    samples.get(0).value mustBe 1.0
    samples.get(0).labelValues must have size expectedLabelCount
    samples.get(0).labelValues.get(0) mustBe expectedMethod
    samples.get(0).labelValues.get(1) mustBe expectedStatus
    samples.get(0).labelValues.get(2) mustBe expectedControllerName
    samples.get(0).labelValues.get(3) mustBe expectedPath
    samples.get(0).labelValues.get(4) mustBe expectedVerb
    samples.get(0).labelValues.get(5) mustBe expectedLatencyBucket
  }

  "StatusCounterFilter" should "Count the requests with status" in {
    // I needed to have an independnt collector per test, otherwise they complain about having duplicate labels.
    val registryThree = new CollectorRegistry(true)
    val promFilter    = new StatusCounterFilter(registryThree)
    val fakeRequest   = FakeRequest()
    val action        = new MockController(stubControllerComponents()).ok

    await(promFilter(action)(fakeRequest).run())

    val metrics = promFilter.requestCounter.collect()
    metrics must have size 1
    val samples = metrics.get(0).samples
    samples.get(0).value mustBe 1.0
    samples.get(0).labelValues must have size 1
    samples.get(0).labelValues.get(0) mustBe "200"
  }
}

class MockController @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  def ok =
    Action {
      Ok("ok")
    }

  def error =
    Action {
      NotFound("error")
    }
}
