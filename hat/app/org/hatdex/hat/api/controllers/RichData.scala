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
 * 4 / 2017
 */

package org.hatdex.hat.api.controllers

import java.util.UUID
import javax.inject.Inject

import scala.concurrent.{ ExecutionContext, Future }
import scala.util.control.NonFatal

import com.mohiva.play.silhouette.api.Silhouette
import com.mohiva.play.silhouette.api.actions.SecuredRequest
import eu.timepit.refined.auto._
import io.dataswift.models.hat.json.RichDataJsonFormats
import io.dataswift.models.hat._
import io.dataswift.models.hat.applications.HatApplication
import org.hatdex.hat.api.service.UsersService
import org.hatdex.hat.api.service.applications.{ ApplicationsService, TrustedApplicationProvider }
import org.hatdex.hat.api.service.monitoring.HatDataEventDispatcher
import org.hatdex.hat.api.service.richData.{ RichDataServiceException, _ }
import org.hatdex.hat.authentication.models._
import org.hatdex.hat.authentication.{ ContainsApplicationRole, HatApiAuthEnvironment, HatApiController, WithRole }
import org.hatdex.hat.utils.{ HatBodyParsers, LoggingProvider }
import org.hatdex.libs.dal.HATPostgresProfile
import play.api.Configuration
import play.api.libs.json.Reads._
import play.api.libs.json.{ JsArray, JsValue, Json }
import play.api.libs.ws.WSClient
import play.api.mvc._

class RichData @Inject() (
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

  /**
    * Returns Data Records for a given endpoint
    *
    * @param namespace Namespace of the endpoint, typically restricted to a specific application
    * @param endpoint  Endpoint name within the namespace, any valid URL path
    * @param orderBy   Data Field within a data record by which data should be ordered
    * @param ordering  The ordering to use for data sorting - default is "ascending", set to "descending" for reverse order
    * @param skip      How many records to skip (used for paging)
    * @param take      How many data records to take - limits the number of results, could be used for paging responses
    * @return HTTP Response with JSON-serialized data records or an error message
    */
  def getEndpointData(
      namespace: String,
      endpoint: String,
      orderBy: Option[String],
      ordering: Option[String],
      skip: Option[Int],
      take: Option[Int]): Action[AnyContent] =
    SecuredAction(
      WithRole(Owner(), NamespaceRead(namespace)) || ContainsApplicationRole(
          Owner(),
          NamespaceRead(namespace)
        )
    ).async { implicit request =>
      makeData(namespace, endpoint, orderBy, ordering, skip, take)
    }

  def saveEndpointData(
      namespace: String,
      endpoint: String,
      skipErrors: Option[Boolean]): Action[JsValue] =
    SecuredAction(
      WithRole(NamespaceWrite(namespace)) || ContainsApplicationRole(
          NamespaceWrite(namespace)
        )
    )
      .async(parsers.json[JsValue]) { implicit request =>
        val dataEndpoint = s"$namespace/$endpoint"
        val response = request.body match {
          case array: JsArray =>
            // TODO: extract unique ID and timestamp
            val values = array.value.map(
              EndpointData(dataEndpoint, None, None, None, _, None)
            )
            dataService
              .saveData(
                request.identity.userId,
                values,
                skipErrors.getOrElse(false)
              )
              .andThen(
                dataEventDispatcher
                  .dispatchEventDataCreated(s"saved batch for $dataEndpoint")
              )
              .map(saved => Created(Json.toJson(saved)))

          case value: JsValue =>
            // TODO: extract unique ID and timestamp
            val values =
              Seq(EndpointData(dataEndpoint, None, None, None, value, None))
            dataService
              .saveData(request.identity.userId, values)
              .andThen(
                dataEventDispatcher
                  .dispatchEventDataCreated(s"saved data for $dataEndpoint")
              )
              .map(saved => Created(Json.toJson(saved.head)))
        }

        response recover {
          case e: RichDataDuplicateException =>
            BadRequest(Json.toJson(Errors.richDataDuplicate(e)))
          case e: RichDataServiceException =>
            BadRequest(Json.toJson(Errors.richDataError(e)))
        }
      }

  def deleteEndpointData(
      namespace: String,
      endpoint: String): Action[AnyContent] =
    SecuredAction(
      WithRole(NamespaceWrite(namespace)) || ContainsApplicationRole(
          NamespaceWrite(namespace)
        )
    ).async { implicit request =>
      val dataEndpoint = s"$namespace/$endpoint"
      dataService.deleteEndpoint(dataEndpoint) map { _ =>
        Ok(Json.toJson(SuccessResponse(s"All records deleted")))
      }
    }

  def saveBatchData: Action[Seq[EndpointData]] =
    SecuredAction(
      WithRole(DataCredit(""), Owner()) || ContainsApplicationRole(
          NamespaceWrite("*"),
          Owner()
        )
    )
      .async(parsers.json[Seq[EndpointData]]) { implicit request =>
        val response = request2ApplicationStatus(request).flatMap { maybeAppStatus =>
          if (authorizeEndpointDataWrite(request.body, maybeAppStatus))
            dataService
              .saveData(request.identity.userId, request.body)
              .andThen(
                dataEventDispatcher
                  .dispatchEventDataCreated(s"saved batch data")
              )
              .map(d => Created(Json.toJson(d)))
          else
            Future.failed(
              RichDataPermissionsException(
                "No rights to insert some or all of the data in the batch"
              )
            )
        }

        response recover {
          case e: RichDataDuplicateException =>
            BadRequest(Json.toJson(Errors.richDataError(e)))
          case e: RichDataPermissionsException =>
            Forbidden(Json.toJson(Errors.forbidden(e)))
          case e: RichDataServiceException =>
            BadRequest(Json.toJson(Errors.richDataError(e)))
        }
      }

  private def endpointDataNamespaces(data: EndpointData): Set[String] =
    data.endpoint.split('/').headOption map { namespace =>
      val namespaces = data.links map { linkedData =>
          linkedData
            .map(endpointDataNamespaces)
            .reduce((set, namespaces) => set ++ namespaces)
        } getOrElse Set()
      namespaces + namespace
    } getOrElse Set()

  // Extract to namespace library
  private def authorizeEndpointDataWrite(
      data: Seq[EndpointData],
      appStatus: Option[HatApplication]
    )(implicit
      user: HatUser,
      authenticator: HatApiAuthEnvironment#A): Boolean =
    data
      .map(endpointDataNamespaces)
      .reduce((set, namespaces) => set ++ namespaces)
      .map(namespace => NamespaceWrite(namespace))
      .forall(role =>
        WithRole.isAuthorized(user, authenticator, role) || appStatus.exists(
            ContainsApplicationRole.isAuthorized(user, _, authenticator, role)
          )
      )

  def registerCombinator(combinator: String): Action[Seq[EndpointQuery]] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner()))
      .async(parsers.json[Seq[EndpointQuery]]) { implicit request =>
        bundleService.saveCombinator(combinator, request.body) map { _ =>
          Created(
            Json.toJson(SuccessResponse(s"Combinator $combinator registered"))
          )
        }
      }

  def getCombinatorData(
      combinator: String,
      orderBy: Option[String],
      ordering: Option[String],
      skip: Option[Int],
      take: Option[Int]): Action[AnyContent] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner())).async { implicit request =>
      val result = for {
        query <- bundleService.combinator(combinator).map(_.get)
        data <- dataService.propertyData(
                  query,
                  orderBy,
                  ordering.contains("descending"),
                  skip.getOrElse(0),
                  take.orElse(Some(defaultRecordLimit))
                )
      } yield data

      result map { d =>
        Ok(Json.toJson(d))
      } recover {
        case NonFatal(_) =>
          NotFound(Json.toJson(Errors.dataCombinatorNotFound(combinator)))
      }
    }

  def linkDataRecords(records: Seq[UUID]): Action[AnyContent] =
    SecuredAction(
      WithRole(DataCredit(""), Owner()) || ContainsApplicationRole(
          NamespaceWrite("*"),
          Owner()
        )
    ).async { implicit request =>
      dataService.saveRecordGroup(request.identity.userId, records) map { _ =>
        Created(Json.toJson(SuccessResponse(s"Grouping registered")))
      } recover {
        case RichDataMissingException(message, _) =>
          BadRequest(Json.toJson(Errors.dataLinkMissing(message)))
      }
    }

  def deleteDataRecords(records: Seq[UUID]): Action[AnyContent] =
    SecuredAction(
      WithRole(DataCredit(""), Owner()) || ContainsApplicationRole(
          NamespaceWrite("*"),
          Owner()
        )
    ).async { implicit request =>
      val eventualPermissionContext = for {
        maybeAppStatus <- request2ApplicationStatus(request)
        recordNamespaces <- dataService.uniqueRecordNamespaces(records)
      } yield (maybeAppStatus, recordNamespaces)

      eventualPermissionContext flatMap {
        case (Some(appStatus), requiredNamespaces)
            if requiredNamespaces.forall(n =>
              ContainsApplicationRole
                .isAuthorized(
                  request.identity,
                  appStatus,
                  request.authenticator,
                  NamespaceWrite(n)
                )
            ) =>
          dataService.deleteRecords(request.identity.userId, records) map { _ =>
            Ok(Json.toJson(SuccessResponse(s"All records deleted")))
          } recover {
              case RichDataMissingException(message, _) =>
                BadRequest(Json.toJson(Errors.dataDeleteMissing(message)))
            }
        case (Some(_), _) =>
          Future.successful(
            Forbidden(
              Json.toJson(
                Errors.forbidden(
                  "Permissions to modify records in some of the namespaces missing"
                )
              )
            )
          )
        // TODO: remove after non-application tokens are phased out
        case (None, _) =>
          dataService.deleteRecords(request.identity.userId, records) map { _ =>
            Ok(Json.toJson(SuccessResponse(s"All records deleted")))
          } recover {
              case RichDataMissingException(message, _) =>
                BadRequest(Json.toJson(Errors.dataDeleteMissing(message)))
            }
      }
    }

  def listEndpoints: Action[AnyContent] =
    SecuredAction(
      WithRole(Owner(), Platform(), DataCredit("")) || ContainsApplicationRole(
          Owner(),
          Platform(),
          NamespaceWrite("*")
        )
    ).async { implicit request =>
      dataService.listEndpoints() map { endpoints =>
        Ok(Json.toJson(endpoints))
      }
    }

  def updateRecords(): Action[Seq[EndpointData]] =
    SecuredAction(
      WithRole(DataCredit(""), Owner()) || ContainsApplicationRole(
          NamespaceWrite("*"),
          Owner()
        )
    )
      .async(parsers.json[Seq[EndpointData]]) { implicit request =>
        request2ApplicationStatus(request).flatMap { maybeAppStatus =>
          if (authorizeEndpointDataWrite(request.body, maybeAppStatus))
            dataService.updateRecords(
              request.identity.userId,
              request.body
            ) map { saved =>
              Created(Json.toJson(saved))
            } recover {
              case RichDataMissingException(message, _) =>
                BadRequest(Json.toJson(Errors.dataUpdateMissing(message)))
            }
          else
            Future.failed(
              RichDataPermissionsException(
                "No rights to update some or all of the data requested"
              )
            )
        }
      }

  def registerBundle(bundleId: String): Action[Map[String, PropertyQuery]] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner()))
      .async(parsers.json[Map[String, PropertyQuery]]) { implicit request =>
        bundleService
          .saveBundle(EndpointDataBundle(bundleId, request.body))
          .map { _ =>
            Created(
              Json.toJson(SuccessResponse(s"Bundle $bundleId registered"))
            )
          }
      }

  def fetchBundle(bundleId: String): Action[AnyContent] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner())).async { implicit request =>
      val result = for {
        bundle <- bundleService.bundle(bundleId).map(_.get)
        data <- dataService.bundleData(bundle)
      } yield data

      result map { d =>
        Ok(Json.toJson(d))
      } recover {
        case NonFatal(_) =>
          NotFound(Json.toJson(Errors.bundleNotFound(bundleId)))
      }
    }

  def bundleStructure(bundleId: String): Action[AnyContent] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner())).async { implicit request =>
      val result = for {
        bundle <- bundleService.bundle(bundleId).map(_.get)
      } yield bundle

      result map { d =>
        Ok(Json.toJson(d))
      } recover {
        case NonFatal(_) =>
          NotFound(Json.toJson(Errors.bundleNotFound(bundleId)))
      }
    }

  def registerDataDebit(dataDebitId: String): Action[DataDebitRequest] =
    SecuredAction(
      WithRole(
        Owner(),
        DataDebitOwner(""),
        Platform()
      ) || ContainsApplicationRole(Owner(), DataDebitOwner(""), Platform())
    ).async(parsers.json[DataDebitRequest]) { implicit request =>
      dataDebitService
        .createDataDebit(dataDebitId, request.body, request.identity.userId)
        .andThen(
          dataEventDispatcher
            .dispatchEventDataDebit(DataDebitOperations.Create())
        )
        .map(debit => Created(Json.toJson(debit)))
        .recover {
          case err: RichDataDuplicateBundleException =>
            BadRequest(Json.toJson(Errors.dataDebitMalformed(err)))
          case err: RichDataDuplicateDebitException =>
            BadRequest(Json.toJson(Errors.dataDebitMalformed(err)))
        }
    }

  def updateDataDebit(dataDebitId: String): Action[DataDebitRequest] =
    SecuredAction(
      WithRole(Owner(), DataDebitOwner(dataDebitId)) || ContainsApplicationRole(
          Owner(),
          DataDebitOwner(dataDebitId)
        )
    ).async(parsers.json[DataDebitRequest]) { implicit request =>
      dataDebitService
        .updateDataDebitBundle(
          dataDebitId,
          request.body,
          request.identity.userId
        )
        .andThen(
          dataEventDispatcher
            .dispatchEventDataDebit(DataDebitOperations.Change())
        )
        .map(debit => Ok(Json.toJson(debit)))
        .recover {
          case err: RichDataServiceException =>
            BadRequest(Json.toJson(Errors.dataDebitMalformed(err)))
        }
    }

  def getDataDebit(dataDebitId: String): Action[AnyContent] =
    SecuredAction(
      WithRole(Owner(), DataDebitOwner(dataDebitId)) || ContainsApplicationRole(
          Owner(),
          DataDebitOwner(dataDebitId)
        )
    ).async { implicit request =>
      dataDebitService
        .dataDebit(dataDebitId)
        .map {
          case Some(debit) => Ok(Json.toJson(debit))
          case None =>
            NotFound(Json.toJson(Errors.dataDebitNotFound(dataDebitId)))
        }
    }

  def getDataDebitValues(dataDebitId: String): Action[AnyContent] =
    SecuredAction(
      WithRole(Owner(), DataDebitOwner(dataDebitId)) || ContainsApplicationRole(
          Owner(),
          DataDebitOwner(dataDebitId)
        )
    ).async { implicit request =>
      dataDebitService
        .dataDebit(dataDebitId)
        .flatMap {
          case Some(debit) if debit.activeBundle.isDefined =>
            logger.debug("Got Data Debit, fetching data")
            val eventualData = debit.activeBundle.get.conditions map { bundleConditions =>
              logger.debug("Getting data for conditions")
              dataService.bundleData(bundleConditions).flatMap { conditionValues =>
                val conditionFulfillment: Map[String, Boolean] =
                  conditionValues map {
                      case (condition, values) =>
                        (condition, values.nonEmpty)
                    }

                if (conditionFulfillment.forall(_._2)) {
                  logger
                    .debug(s"Data Debit $dataDebitId conditions satisfied")
                  dataService
                    .bundleData(debit.activeBundle.get.bundle)
                    .map(RichDataDebitData(Some(conditionFulfillment), _))
                } else {
                  logger.debug(
                    s"Data Debit $dataDebitId conditions not satisfied: $conditionFulfillment"
                  )
                  Future.successful(
                    RichDataDebitData(Some(conditionFulfillment), Map())
                  )
                }
              }

            } getOrElse {
              logger.debug(s"Data Debit $dataDebitId without conditions")
              dataService
                .bundleData(debit.activeBundle.get.bundle)
                .map(RichDataDebitData(None, _))
            }

            eventualData
              .andThen(dataEventDispatcher.dispatchEventDataDebitValues(debit))
              .map(d => Ok(Json.toJson(d)))

          case Some(_) =>
            Future.successful(
              BadRequest(Json.toJson(Errors.dataDebitNotEnabled(dataDebitId)))
            )
          case None =>
            Future.successful(
              NotFound(Json.toJson(Errors.dataDebitNotFound(dataDebitId)))
            )
        }
        .recover {
          case err: RichDataBundleFormatException =>
            BadRequest(
              Json.toJson(Errors.dataDebitBundleMalformed(dataDebitId, err))
            )
        }
    }

  def listDataDebits(): Action[AnyContent] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner())).async { implicit request =>
      dataDebitService.all map { debits =>
        Ok(Json.toJson(debits))
      }
    }

  def enableDataDebitBundle(
      dataDebitId: String,
      bundleId: String): Action[AnyContent] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner())).async { implicit request =>
      enableDataDebit(dataDebitId, Some(bundleId))
    }

  def enableDataDebitNewest(dataDebitId: String): Action[AnyContent] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner())).async { implicit request =>
      enableDataDebit(dataDebitId, None)
    }

  protected def enableDataDebit(
      dataDebitId: String,
      bundleId: Option[String]
    )(implicit request: SecuredRequest[HatApiAuthEnvironment, AnyContent]): Future[Result] = {
    val enabled = for {
      _ <- dataDebitService.dataDebitEnableBundle(dataDebitId, bundleId)
      debit <- dataDebitService.dataDebit(dataDebitId)
    } yield debit

    enabled
      .andThen(
        dataEventDispatcher
          .dispatchEventMaybeDataDebit(DataDebitOperations.Enable())
      )
      .map {
        case Some(debit) => Ok(Json.toJson(debit))
        case None        => BadRequest(Json.toJson(Errors.dataDebitDoesNotExist))
      }
  }

  def disableDataDebit(dataDebitId: String): Action[AnyContent] =
    SecuredAction(WithRole(Owner()) || ContainsApplicationRole(Owner())).async { implicit request =>
      val disabled = for {
        _ <- dataDebitService.dataDebitDisable(dataDebitId)
        debit <- dataDebitService.dataDebit(dataDebitId)
      } yield debit

      disabled
        .andThen(
          dataEventDispatcher
            .dispatchEventMaybeDataDebit(DataDebitOperations.Disable())
        )
        .map {
          case Some(debit) => Ok(Json.toJson(debit))
          case None        => BadRequest(Json.toJson(Errors.dataDebitDoesNotExist))
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

  private object Errors {
    def dataDebitDoesNotExist: ErrorMessage =
      ErrorMessage("Not Found", "Data Debit with this ID does not exist")
    def dataDebitNotFound(id: String): ErrorMessage =
      ErrorMessage("Not Found", s"Data Debit $id not found")
    def dataDebitNotEnabled(id: String): ErrorMessage =
      ErrorMessage("Bad Request", s"Data Debit $id not enabled")
    def dataDebitMalformed(err: Throwable): ErrorMessage =
      ErrorMessage(
        "Bad Request",
        s"Data Debit request malformed: ${err.getMessage}"
      )
    def dataDebitBundleMalformed(
        id: String,
        err: Throwable): ErrorMessage =
      ErrorMessage(
        "Data Debit Bundle malformed",
        s"Data Debit $id active bundle malformed: ${err.getMessage}"
      )

    def bundleNotFound(bundleId: String): ErrorMessage =
      ErrorMessage("Bundle Not Found", s"Bundle $bundleId not found")

    def dataUpdateMissing(message: String): ErrorMessage =
      ErrorMessage("Data Missing", s"Could not update records: $message")
    def dataDeleteMissing(message: String): ErrorMessage =
      ErrorMessage("Data Missing", s"Could not delete records: $message")
    def dataLinkMissing(message: String): ErrorMessage =
      ErrorMessage("Data Missing", s"Could not link records: $message")

    def dataCombinatorNotFound(combinator: String): ErrorMessage =
      ErrorMessage("Combinator Not Found", s"Combinator $combinator not found")

    def richDataDuplicate(error: Throwable): ErrorMessage =
      ErrorMessage("Bad Request", s"Duplicate data - ${error.getMessage}")
    def richDataError(error: Throwable): ErrorMessage =
      ErrorMessage(
        "Bad Request",
        s"Could not insert data - ${error.getMessage}"
      )
    def forbidden(error: Throwable): ErrorMessage =
      ErrorMessage("Forbidden", s"Access Denied - ${error.getMessage}")
    def forbidden(message: String): ErrorMessage =
      ErrorMessage("Forbidden", s"Access Denied - ${message}")
  }
}
