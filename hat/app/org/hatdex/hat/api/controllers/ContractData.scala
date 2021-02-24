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
 * Written by Tyler Weir <tyler.weir@dataswift.io>
 * 1 / 2021
 */

package org.hatdex.hat.api.controllers

import java.util.UUID
import javax.inject.Inject

import scala.concurrent.{ ExecutionContext, Future }
import scala.util.{ Failure, Success }

import com.mohiva.play.silhouette.api.Silhouette
import dev.profunktor.auth.jwt.JwtSecretKey
import eu.timepit.refined._
import eu.timepit.refined.auto._
import eu.timepit.refined.collection.NonEmpty
import io.dataswift.adjudicator.ShortLivedTokenOps
import io.dataswift.adjudicator.Types.{ ContractId, HatName, ShortLivedToken }
import org.hatdex.hat.NamespaceUtils.NamespaceUtils
import org.hatdex.hat.api.controllers.RequestValidationFailure._
import io.dataswift.models.hat.json.RichDataJsonFormats
import io.dataswift.models.hat._
import io.dataswift.models.hat.applications.Application
import org.hatdex.hat.api.service.UsersService
import org.hatdex.hat.api.service.applications.{ ApplicationsService, TrustedApplicationProvider }
import org.hatdex.hat.api.service.monitoring.HatDataEventDispatcher
import org.hatdex.hat.api.service.richData._
import org.hatdex.hat.authentication.models._
import org.hatdex.hat.authentication.{ HatApiAuthEnvironment, HatApiController }
import org.hatdex.hat.resourceManagement.HatServer
import org.hatdex.hat.utils.AdjudicatorRequestTypes._
import org.hatdex.hat.utils.{ AdjudicatorRequest, HatBodyParsers, LoggingProvider }
import org.hatdex.libs.dal.HATPostgresProfile
import pdi.jwt.JwtClaim
import play.api.Configuration
import play.api.libs.json.Reads._
import play.api.libs.json.{ JsArray, JsValue, Json, Reads }
import play.api.libs.ws.WSClient
import play.api.mvc._

sealed trait RequestValidationFailure
object RequestValidationFailure {
  final case class HatNotFound(hatName: String) extends RequestValidationFailure
  final case class MissingHatName(hatName: String) extends RequestValidationFailure
  final case class InaccessibleNamespace(namespace: String) extends RequestValidationFailure
  final case class InvalidShortLivedToken(contractId: String) extends RequestValidationFailure
  final case object GeneralError extends RequestValidationFailure
}
final case class RequestVerified(namespace: String) extends AnyVal

class ContractData @Inject() (
    components: ControllerComponents,
    parsers: HatBodyParsers,
    silhouette: Silhouette[HatApiAuthEnvironment],
    dataEventDispatcher: HatDataEventDispatcher,
    dataService: RichDataService,
    bundleService: RichBundleService,
    dataDebitService: DataDebitContractService,
    loggingProvider: LoggingProvider,
    configuration: Configuration,
    usersService: UsersService,
    trustedApplicationProvider: TrustedApplicationProvider,
    implicit val ec: ExecutionContext,
    implicit val applicationsService: ApplicationsService
  )(wsClient: WSClient)
    extends HatApiController(components, silhouette)
    with RichDataJsonFormats {

  private val logger             = loggingProvider.logger(this.getClass)
  private val defaultRecordLimit = 1000

  // Adjudicator
  private val adjudicatorAddress =
    configuration.underlying.getString("adjudicator.address")
  private val adjudicatorScheme =
    configuration.underlying.getString("adjudicator.scheme")
  private val adjudicatorEndpoint =
    s"${adjudicatorScheme}${adjudicatorAddress}"
  private val adjudicatorSharedSecret =
    configuration.underlying.getString("adjudicator.sharedSecret")
  private val adjudicatorClient = new AdjudicatorRequest(
    adjudicatorEndpoint,
    JwtSecretKey(adjudicatorSharedSecret),
    wsClient
  )

  // Types
  case class ContractDataInfoRefined(
      token: ShortLivedToken,
      hatName: HatName,
      contractId: ContractId)

  case class ContractDataReadRequest(
      token: String,
      hatName: String,
      contractId: String)
  implicit val contractDataReadRequestReads: Reads[ContractDataReadRequest] = Json.reads[ContractDataReadRequest]

  case class ContractDataCreateRequest(
      token: String,
      hatName: String,
      contractId: String,
      body: Option[JsValue])
  implicit val contractDataCreateRequestReads: Reads[ContractDataCreateRequest] = Json.reads[ContractDataCreateRequest]

  case class ContractDataUpdateRequest(
      token: String,
      hatName: String,
      contractId: String,
      body: Seq[EndpointData])
  implicit val contractDataUpdateRequestReads: Reads[ContractDataUpdateRequest] = Json.reads[ContractDataUpdateRequest]

  // Errors
  sealed abstract class ContractVerificationFailure
  object ContractVerificationFailure {
    final case class ServiceRespondedWithFailure(failureDescription: String) extends ContractVerificationFailure
    final case class InvalidTokenFailure(failureDescription: String) extends ContractVerificationFailure
    final case class InvalidContractDataRequestFailure(
        failureDescription: String)
        extends ContractVerificationFailure
  }
  sealed abstract class ContractVerificationSuccess
  object ContractVerificationSuccess {
    final case class JwtClaimVerified(jwtClaim: JwtClaim) extends ContractVerificationSuccess
  }

  // -- Error Handler
  def handleFailedRequestAssessment(failure: RequestValidationFailure): Future[Result] =
    failure match {
      case HatNotFound(hatName)               => Future.successful(BadRequest(s"HatName not found: ${hatName}"))
      case MissingHatName(hatName)            => Future.successful(BadRequest(s"Missing HatName: ${hatName}"))
      case InaccessibleNamespace(namespace)   => Future.successful(BadRequest(s"Namespace Inaccessible: ${namespace}"))
      case InvalidShortLivedToken(contractId) => Future.successful(BadRequest(s"Invalid Token: ${contractId}"))
      case GeneralError                       => Future.successful(BadRequest("Unknown Error"))
    }

  // -- Operations

  // -- Create
  def handleCreateContractData(
      hatUser: HatUser,
      contractDataCreate: ContractDataCreateRequest,
      namespace: String,
      endpoint: String,
      skipErrors: Option[Boolean]
    )(implicit hatServer: HatServer): Future[Result] =
    contractDataCreate.body match {
      // Missing Json Body, do nothing, return error
      case None =>
        logger.error(s"saveContractData included no json body - ns:${namespace} - endpoint:${endpoint}")
        Future.successful(NotFound)
      // There is a Json body, process either an JsArray or a JsValue
      case Some(jsBody) =>
        val dataEndpoint = s"$namespace/$endpoint"
        jsBody match {
          case array: JsArray =>
            logger.info(s"saveContractData.body is JsArray: ${contractDataCreate.body}")
            handleJsArray(
              hatUser.userId,
              array,
              dataEndpoint,
              skipErrors
            )
          case value: JsValue =>
            logger.info(s"saveContractData.body is JsValue: ${contractDataCreate.body}")
            handleJsValue(
              hatUser.userId,
              value,
              dataEndpoint
            )
        }
    }

  // -- Update
  def handleUpdateContractData(
      hatUser: HatUser,
      contractDataUpdate: ContractDataUpdateRequest,
      namespace: String
    )(implicit hatServer: HatServer): Future[Result] =
    contractDataUpdate.body.length match {
      // Missing Json Body, do nothing, return error
      case 0 =>
        logger.error(s"updateContractData included no json body - ns:${namespace}")
        Future.successful(NotFound)
      // There is a Json body, process either an JsArray or a JsValue
      case _ =>
        val dataSeq = contractDataUpdate.body.map(item => item.copy(endpoint = s"${namespace}/${item.endpoint}"))
        dataService.updateRecords(
          hatUser.userId,
          dataSeq
        ) map { saved =>
          Created(Json.toJson(saved))
        } recover {
          case RichDataMissingException(message, _) =>
            BadRequest(Json.toJson(ErrorsFromRichData.dataUpdateMissing(message)))
        }
    }

  // --- API Handlers ---

  def readContractData(
      namespace: String,
      endpoint: String,
      orderBy: Option[String],
      ordering: Option[String],
      skip: Option[Int],
      take: Option[Int]): Action[ContractDataReadRequest] =
    UserAwareAction.async(parsers.json[ContractDataReadRequest]) { implicit request =>
      val contractDataRead      = request.body
      val maybeContractDataInfo = refineContractDataReadRequest(contractDataRead)
      maybeContractDataInfo match {
        case Some(contractDataInfo) =>
          contractValid(contractDataInfo, namespace).flatMap { contractOk =>
            contractOk match {
              case (Some(_hatUser @ _), Right(RequestVerified(_ns @ _))) =>
                makeData(namespace, endpoint, orderBy, ordering, skip, take)
              case (_, Left(x)) => handleFailedRequestAssessment(x)
              case (None, Right(_)) =>
                logger.warn(s"ReadContract: Hat not found for:  ${contractDataRead}")
                handleFailedRequestAssessment(HatNotFound(contractDataInfo.hatName.toString))
              case (_, _) =>
                logger.warn(s"ReadContract: Fallback Error case for: ${contractDataRead}")
                handleFailedRequestAssessment(GeneralError)
            }
          }
        case None => Future.successful(BadRequest("Missing Contract Details."))
      }
    }

  def createContractData(
      namespace: String,
      endpoint: String,
      skipErrors: Option[Boolean]): Action[ContractDataCreateRequest] =
    UserAwareAction.async(parsers.json[ContractDataCreateRequest]) { implicit request =>
      val contractDataCreate    = request.body
      val maybeContractDataInfo = refineContractDataCreateRequest(contractDataCreate)
      maybeContractDataInfo match {
        case Some(contractDataInfo) =>
          contractValid(contractDataInfo, namespace).flatMap { contractOk =>
            contractOk match {
              case (Some(hatUser), Right(RequestVerified(_ns))) =>
                handleCreateContractData(hatUser, contractDataCreate, namespace, endpoint, skipErrors)
              case (_, Left(x)) => handleFailedRequestAssessment(x)
              case (None, Right(_)) =>
                logger.warn(s"CreateContract: Hat not found for:  ${contractDataCreate}")
                handleFailedRequestAssessment(HatNotFound(contractDataInfo.hatName.toString))
              case (_, _) =>
                logger.warn(s"CreateContract: Fallback Error case for: ${contractDataCreate}")
                handleFailedRequestAssessment(GeneralError)
            }
          }
        case None => Future.successful(BadRequest("Missing Contract Details."))
      }
    }

  def updateContractData(namespace: String): Action[ContractDataUpdateRequest] =
    UserAwareAction.async(parsers.json[ContractDataUpdateRequest]) { implicit request =>
      val contractDataUpdate    = request.body
      val maybeContractDataInfo = refineContractDataUpdateRequest(contractDataUpdate)
      maybeContractDataInfo match {
        case Some(contractDataInfo) =>
          contractValid(contractDataInfo, namespace).flatMap { contractOk =>
            contractOk match {
              case (Some(hatUser), Right(RequestVerified(ns))) =>
                handleUpdateContractData(hatUser, contractDataUpdate, ns)
              case (_, Left(x)) => handleFailedRequestAssessment(x)
              case (None, Right(_)) =>
                logger.warn(s"UpdateContract: Hat not found for:  ${contractDataUpdate}")
                handleFailedRequestAssessment(HatNotFound(contractDataInfo.hatName.toString))
              case (_, _) =>
                logger.warn(s"UpdateContract: Fallback Error case for:  ${contractDataUpdate}")
                handleFailedRequestAssessment(GeneralError)
            }
          }
        case None => Future.successful(BadRequest("Missing Contract Details."))
      }
    }

  private def makeData(
      namespace: String,
      endpoint: String,
      orderBy: Option[String],
      ordering: Option[String],
      skip: Option[Int],
      take: Option[Int]
    )(implicit db: HATPostgresProfile.api.Database): Future[Result] = {
    val dataEndpoint = s"$namespace/$endpoint"
    val query =
      Seq(EndpointQuery(dataEndpoint, None, None, None))
    val data = dataService.propertyData(
      query,
      orderBy,
      ordering.contains("descending"),
      skip.getOrElse(0),
      take.orElse(Some(defaultRecordLimit))
    )
    data.map(d => Ok(Json.toJson(d)))
  }

  trait ContractRequest {
    def refineContract: ContractDataInfoRefined
  }

  def refineContractInfo(
      token: String,
      hatName: String,
      contractId: String): Option[ContractDataInfoRefined] =
    for {
      tokenR <- refineV[NonEmpty](token).toOption
      hatNameR <- refineV[NonEmpty](hatName).toOption
      contractIdR <- refineV[NonEmpty](contractId).toOption
      contractDataInfoRefined = ContractDataInfoRefined(
                                  ShortLivedToken(tokenR),
                                  HatName(hatNameR),
                                  ContractId(UUID.fromString(contractIdR))
                                )
    } yield contractDataInfoRefined

  def refineContractDataReadRequest(req: ContractDataReadRequest): Option[ContractDataInfoRefined] =
    refineContractInfo(req.token, req.hatName, req.contractId)

  def refineContractDataCreateRequest(req: ContractDataCreateRequest): Option[ContractDataInfoRefined] =
    refineContractInfo(req.token, req.hatName, req.contractId)

  def refineContractDataUpdateRequest(req: ContractDataUpdateRequest): Option[ContractDataInfoRefined] =
    refineContractInfo(req.token, req.hatName, req.contractId)

  def contractValid(
      contract: ContractDataInfoRefined,
      namespace: String
    )(implicit hatServer: HatServer): Future[(Option[HatUser], Either[RequestValidationFailure, RequestVerified])] =
    for {
      hatUser <- usersService.getUser(contract.hatName.value)
      requestAssestment <- assessRequest(contract, namespace)
    } yield (hatUser, requestAssestment)

  def handleJsArray(
      userId: UUID,
      array: JsArray,
      dataEndpoint: String,
      skipErrors: Option[Boolean]
    )(implicit hatServer: HatServer): Future[Result] = {
    val values =
      array.value.map(EndpointData(dataEndpoint, None, None, None, _, None))
    logger.info(s"handleJsArray: Values: ${values}")
    dataService
      .saveData(userId, values, skipErrors.getOrElse(false))
      .map(saved => Created(Json.toJson(saved)))
  }

  def handleJsValue(
      userId: UUID,
      value: JsValue,
      dataEndpoint: String
    )(implicit hatServer: HatServer): Future[Result] = {
    val values = Seq(EndpointData(dataEndpoint, None, None, None, value, None))
    logger.info(s"handleJsArray: Values: ${values}")
    dataService
      .saveData(userId, values)
      .map(saved => Created(Json.toJson(saved.head)))
  }

  def verifyNamespace(
      app: Application,
      namespace: String): Boolean = {
    logger.info(s"verifyNamespace ${namespace} for app ${app}")

    val canReadNamespace  = verifyNamespaceRead(app, namespace)
    val canWriteNamespace = verifyNamespaceWrite(app, namespace)

    logger.info(
      s"def verifyNamespace read: ${canReadNamespace} - write: ${canWriteNamespace}"
    )

    (canReadNamespace || canWriteNamespace)
  }

  def verifyNamespaceRead(
      app: Application,
      namespace: String): Boolean = {
    val rolesOk = NamespaceUtils.testReadNamespacePermissions(app.permissions.rolesGranted, namespace)
    logger.info(
      s"NamespaceRead: AppPerms: ${app.permissions}, RolesOk: ${rolesOk}, namespace: ${namespace}, result: ${rolesOk}"
    )

    rolesOk
  }

  def verifyNamespaceWrite(
      app: Application,
      namespace: String): Boolean = {
    val rolesOk = NamespaceUtils.testWriteNamespacePermissions(app.permissions.rolesGranted, namespace)
    logger.info(
      s"NamespaceWrite: AppPerms: ${app.permissions}, RolesOk: ${rolesOk}, namespace: ${namespace}, result: ${rolesOk}"
    )

    rolesOk
  }

  // TODO: Use KeyId
  private def requestKeyId(
      contractDataInfo: ContractDataInfoRefined): Option[String] =
    for {
      keyId <- ShortLivedTokenOps
                 .getKeyId(contractDataInfo.token.value)
                 .toOption
    } yield keyId

  def verifyContract(contractDataInfo: ContractDataInfoRefined): Future[
    Either[ContractVerificationFailure, ContractVerificationSuccess]
  ] = {
    import ContractVerificationFailure._

    // This logic is tied up with special types
    val maybeContractDataRequestKeyId = for {
      keyId <- requestKeyId(contractDataInfo)
    } yield keyId

    maybeContractDataRequestKeyId match {
      case Some(keyId) =>
        logger.info(s"ContractData-keyId: ${keyId}")
        verifyTokenWithAdjudicator(contractDataInfo, keyId)
      case _ =>
        Future.successful(
          Left(
            InvalidContractDataRequestFailure(
              "Contract Data Request or KeyId missing"
            )
          )
        )
    }
  }

  def verifyJwtClaim(
      contractRequestBodyRefined: ContractDataInfoRefined,
      publicKeyAsByteArray: Array[Byte]): Either[ContractVerificationFailure, ContractVerificationSuccess] = {
    import ContractVerificationFailure._
    import ContractVerificationSuccess._

    logger.error(
      s"ContractData.verifyJwtClaim.token: ${contractRequestBodyRefined.token.toString}"
    )
    logger.error(
      s"ContractData.verifyJwtClaim.pubKey: ${publicKeyAsByteArray}"
    )

    val tryJwtClaim = ShortLivedTokenOps.verifyToken(
      Some(contractRequestBodyRefined.token.toString),
      publicKeyAsByteArray
    )
    tryJwtClaim match {
      case Success(jwtClaim) => Right(JwtClaimVerified(jwtClaim))
      case Failure(errorMsg) =>
        logger.error(
          s"ContractData.verifyJwtClaim.failureMessage: ${errorMsg.getMessage}"
        )
        Left(
          InvalidTokenFailure(
            s"Token: ${contractRequestBodyRefined.token.toString} was not verified."
          )
        )
    }
  }

  def verifyTokenWithAdjudicator(
      contractRequestBodyRefined: ContractDataInfoRefined,
      keyId: String): Future[
    Either[ContractVerificationFailure, ContractVerificationSuccess]
  ] =
    adjudicatorClient
      .getPublicKey(
        contractRequestBodyRefined.hatName,
        contractRequestBodyRefined.contractId,
        keyId
      )
      .map { publicKeyResponse =>
        publicKeyResponse match {
          case Left(
                PublicKeyRequestFailure.ServiceRespondedWithFailure(
                  failureDescription
                )
              ) =>
            Left(
              ContractVerificationFailure.ServiceRespondedWithFailure(
                s"The Adjudicator Service responded with an error: ${failureDescription}"
              )
            )
          case Left(
                PublicKeyRequestFailure.InvalidPublicKeyFailure(
                  failureDescription
                )
              ) =>
            Left(
              ContractVerificationFailure.ServiceRespondedWithFailure(
                s"The Adjudicator Service responded with an error: ${failureDescription}"
              )
            )
          case Right(PublicKeyReceived(publicKey)) =>
            verifyJwtClaim(contractRequestBodyRefined, publicKey)
        }
      }

  def assessRequest(
      contractDataInfo: ContractDataInfoRefined,
      namespace: String): Future[Either[RequestValidationFailure, RequestVerified]] = {
    val eventuallyMaybeDecision = verifyContract(contractDataInfo)
    val eventuallyMaybeApp =
      trustedApplicationProvider.application(contractDataInfo.contractId.value.toString())

    eventuallyMaybeDecision.flatMap { maybeDecision =>
      eventuallyMaybeApp.flatMap { maybeApp =>
        logger.info(s"AssessRequest: ${maybeDecision} - ${maybeApp} - ${namespace}")
        decide(maybeDecision, maybeApp, namespace) match {
          case Some(ns) =>
            logger.info(s"Found a namespace: ${ns}")
            Future.successful(
              Right(
                RequestVerified(s"Token: ${contractDataInfo.contractId}")
              )
            )
          case None =>
            logger.error(s"def assessRequest: decide returned None - ${contractDataInfo} - ${namespace}")
            Future.successful(
              Left(
                RequestValidationFailure.InvalidShortLivedToken(
                  s"Token: ${contractDataInfo.contractId}"
                )
              )
            )
        }
      }
    } recover {
      case e =>
        logger.error(s"ContractData.assessRequest:Failure ${e}")
        Left(
          RequestValidationFailure.InvalidShortLivedToken(
            s"Token: ${contractDataInfo.contractId}"
          )
        )
    }
  }

  def decide(
      eitherDecision: Either[
        ContractVerificationFailure,
        ContractVerificationSuccess
      ],
      maybeApp: Option[Application],
      namespace: String): Option[String] = {
    import ContractVerificationSuccess._

    logger.info(s"def decide: decision: ${eitherDecision} - app: ${maybeApp} - ns: ${namespace}")

    (eitherDecision, maybeApp) match {
      case (Right(JwtClaimVerified(_jwtClaim @ _)), Some(app)) =>
        logger.info(s"def decide: JwtClaim verified for app ${app}")
        if (verifyNamespace(app, namespace))
          Some(namespace)
        else
          None
      case (Left(decision), _) =>
        logger.error(s"def decide: decision: ${decision}")
        None
      case (_, _) =>
        logger.error(s"def decide: decision is no.")
        None
    }
  }

  private object ErrorsFromRichData {
    def dataUpdateMissing(message: String): ErrorMessage =
      ErrorMessage("Data Missing", s"Could not update records: $message")
  }
}
