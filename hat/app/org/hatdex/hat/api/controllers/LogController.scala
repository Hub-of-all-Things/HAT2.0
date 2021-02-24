package org.hatdex.hat.api.controllers

import javax.inject.Inject

import scala.util.Try

import com.mohiva.play.silhouette.api.Silhouette
import io.dataswift.models.hat._
import io.dataswift.models.hat.json.HatJsonFormats
import io.dataswift.models.hat.json.LogRequestFormats._
import org.hatdex.hat.api.service.{ LogService, RemoteExecutionContext }
import org.hatdex.hat.authentication.{ HatApiAuthEnvironment, HatApiController }
import org.hatdex.hat.utils.HatBodyParsers
import play.api.Logger
import play.api.libs.json.Json
import play.api.mvc.{ Action, ControllerComponents }

class LogController @Inject() (
    components: ControllerComponents,
    parsers: HatBodyParsers,
    logService: LogService,
    silhouette: Silhouette[HatApiAuthEnvironment]
  )(implicit val ec: RemoteExecutionContext)
    extends HatApiController(components, silhouette)
    with HatJsonFormats {

  private val logger = Logger(this.getClass)

  def logFrontendAction(): Action[LogRequest] =
    SecuredAction.async(parsers.json[LogRequest]) { request =>
      val logRequest = request.body
      val hatAddress = request.dynamicEnvironment.domain
      val appDetails = request.authenticator.customClaims.flatMap { customClaims =>
        Try(
          (
            (customClaims \ "application").as[String],
            (customClaims \ "applicationVersion").as[String]
          )
        ).toOption
      }

      logService
        .logAction(hatAddress, logRequest, appDetails)
        .map { _ =>
          Ok(Json.toJson(SuccessResponse(s"${logRequest.actionCode} logged")))
        }
        .recover {
          case e =>
            logger.error(
              s"Failed to log action ${logRequest.actionCode}. Reason:\n${e.getMessage}"
            )
            InternalServerError(
              Json.toJson(
                ErrorMessage(
                  "Internal server error",
                  s"Could not log ${logRequest.actionCode} action"
                )
              )
            )
        }
    }
}
