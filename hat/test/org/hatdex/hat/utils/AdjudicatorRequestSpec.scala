// /*
//  * Copyright (C) 2020 HAT Data Exchange Ltd
//  * SPDX-License-Identifier: AGPL-3.0
//  *
//  * This file is part of the Hub of All Things project (HAT).
//  *
//  * HAT is free software: you can redistribute it and/or modify
//  * it under the terms of the GNU Affero General Public License
//  * as published by the Free Software Foundation, version 3 of
//  * the License.
//  *
//  * HAT is distributed in the hope that it will be useful, but
//  * WITHOUT ANY WARRANTY; without even the implied warranty of
//  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
//  * the GNU Affero General Public License for more details.
//  *
//  * You should have received a copy of the GNU Affero General
//  * Public License along with this program. If not, see
//  * <http://www.gnu.org/licenses/>.
//  *
//  */

// package org.hatdex.hat.utils

// import com.mohiva.play.silhouette.test._
// import io.dataswift.adjudicator.Types.{ ContractId, HatName }
// import org.hatdex.hat.api.HATTestContext
// import org.hatdex.hat.api.controllers.RichData
// import org.hatdex.hat.api.models._
// import org.hatdex.hat.api.service.richData.{ DataDebitContractService, RichDataService }
// import org.joda.time.LocalDateTime
// import org.specs2.concurrent.ExecutionEnv
// import org.specs2.mock.Mockito
// import org.specs2.specification.{ BeforeAll, BeforeEach }
// import play.api.Logger
// import play.api.libs.json.{ JsArray, JsObject, JsValue, Json }
// import play.api.mvc.{ Action, Result, Results }
// import play.api.test.{ FakeRequest, Helpers, PlaySpecification, WsTestClient }
// import play.api.libs.ws.{ WSClient, WSRequest }
// import eu.timepit.refined._
// import eu.timepit.refined.auto._
// import java.util.UUID

// import akka.util.ByteString
// import play.api.http.HttpEntity
// import play.core.server.Server

// import scala.concurrent.duration._
// import scala.concurrent.{ Await, ExecutionContext, Future }

// class AdjudicatorRequestSpec extends PlaySpecification with Mockito {

//   val logger                                         = Logger(this.getClass)
//   implicit val ec: scala.concurrent.ExecutionContext = scala.concurrent.ExecutionContext.global

//   sequential

//   "The `AdjudicatorRequest should`" should {
//     //** Adjudicator
//     val adjudicatorAddress  = "localhost:9002"
//     val adjudicatorScheme   = "http://"
//     val adjudicatorEndpoint = s"${adjudicatorScheme}${adjudicatorAddress}"

//     val hatName: HatName       = HatName("hatName")
//     val contractId: ContractId = ContractId(UUID.fromString("21a3eed7-5d32-46ba-a884-1fdaf7259739"))

//     "Add a Hat to a Contract" in {
//       WsTestClient.withClient { client =>
//         val adjudicatorClient = new AdjudicatorRequest(adjudicatorEndpoint, client)
//         val joinContract      = adjudicatorClient.joinContract("hatName", contractId)
//         val eventuallyJoinContract = joinContract.map { response =>
//             response match {
//               case Left(l)  => false
//               case Right(r) => true
//             }
//           } recover {
//               case e =>
//                 Future.successful(false)
//             }

//         val result = Await.result(eventuallyJoinContract, 10.seconds)
//         result shouldEqual true
//       }
//     }

//     "Request a PublicKey" in {
//       WsTestClient.withClient { client =>
//         val adjudicatorClient = new AdjudicatorRequest(adjudicatorEndpoint, client)
//         val getPublicKey      = adjudicatorClient.getPublicKey(hatName, contractId, "21a3eed7-5d32-46ba-a884-1fdaf7259739")
//         val eventuallyPublicKey = getPublicKey.map { response =>
//             response match {
//               case Left(l)  => false
//               case Right(r) => true
//             }
//           } recover {
//               case _e =>
//                 Future.successful(false)
//             }

//         val result = Await.result(eventuallyPublicKey, 10.seconds)
//         result shouldEqual true
//       }
//     }

//     "Remove a Hat to a Contract" in {
//       WsTestClient.withClient { client =>
//         val adjudicatorClient = new AdjudicatorRequest(adjudicatorEndpoint, client)
//         val leaveContract     = adjudicatorClient.leaveContract("hatName", contractId)
//         val eventuallyLeaveContract = leaveContract.map { response =>
//             response match {
//               case Left(l)  => false
//               case Right(r) => true
//             }
//           } recover {
//               case e =>
//                 Future.successful(false)
//             }

//         val result = Await.result(eventuallyLeaveContract, 10.seconds)
//         result shouldEqual true
//       }
//     }
//   }
// }
