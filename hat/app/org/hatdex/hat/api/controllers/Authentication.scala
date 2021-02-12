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
 * 3 / 2017
 */

package org.hatdex.hat.api.controllers

import java.net.{ URLDecoder, URLEncoder }

import akka.Done
import javax.inject.Inject
import io.circe.generic.auto._
import io.circe.config.syntax._
import com.mohiva.play.silhouette.api.repositories.AuthInfoRepository
import com.mohiva.play.silhouette.api.util.{ Credentials, PasswordHasherRegistry }
import com.mohiva.play.silhouette.api.{ LoginEvent, Silhouette }
import com.mohiva.play.silhouette.impl.exceptions.{ IdentityNotFoundException, InvalidPasswordException }
import com.mohiva.play.silhouette.impl.providers.CredentialsProvider
import org.hatdex.hat.api.json.HatJsonFormats
import org.hatdex.hat.api.models._
import org.hatdex.hat.api.models.applications.ApplicationSetup
import org.hatdex.hat.api.service.applications.ApplicationsService
import org.hatdex.hat.api.service.{ HatServicesService, LogService, MailTokenService, UsersService }
import org.hatdex.hat.authentication._
import org.hatdex.hat.phata.models._
import org.hatdex.hat.resourceManagement.{ HatServerProvider, _ }
import org.hatdex.hat.utils.{ DataswiftServiceConfig, HatBodyParsers, HatMailer }
import play.api.{ Configuration, Logger }
import play.api.cache.{ Cached, CachedBuilder }
import play.api.i18n.Lang
import play.api.libs.json.Json
import play.api.libs.ws.WSClient
import play.api.mvc.{ Action, _ }

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

class Authentication @Inject() (
    components: ControllerComponents,
    cached: Cached,
    configuration: Configuration,
    parsers: HatBodyParsers,
    hatServerProvider: HatServerProvider,
    silhouette: Silhouette[HatApiAuthEnvironment],
    credentialsProvider: CredentialsProvider[HatServer],
    hatServicesService: HatServicesService,
    passwordHasherRegistry: PasswordHasherRegistry,
    authInfoRepository: AuthInfoRepository[HatServer],
    usersService: UsersService,
    applicationsService: ApplicationsService,
    logService: LogService,
    mailer: HatMailer,
    tokenService: MailTokenService[MailTokenUser],
    wsClient: WSClient,
    limiter: UserLimiter)
    extends HatApiController(components, silhouette)
    with HatJsonFormats {

  private val logger = Logger(this.getClass)

  private val indefiniteSuccessCaching: CachedBuilder = cached
    .status(req => s"${req.host}${req.path}", 200)
    .includeStatus(404, 600)

  private val emailScheme = "https://"

  private val pdaAccountRegistry: DataswiftServiceConfig =
    configuration.underlying.as[DataswiftServiceConfig]("pdaAccountRegistry.verificationCallback").right.get
  private val isSandboxPda: Boolean =
    configuration.getOptional[Boolean]("exchange.beta").getOrElse(true)

  // * Error Responses *
  // Extracted as these messages increased the length of functions.
  // So as a small effort to increase readability, I pulled them out.
  private def unauthorizedMessage(
      title: String,
      body: String) =
    Unauthorized(Json.toJson(ErrorMessage(s"${title}", s"${body}")))

  val noUserMatchingToken =
    unauthorizedMessage("Password reset unauthorized", "No user matching token")

  val onlyHatOwnerCanReset =
    unauthorizedMessage("Password reset unauthorized", "Only HAT owner can reset their password")

  val expiredToken =
    unauthorizedMessage("Invalid Token", "Token expired or invalid")

  val invalidToken =
    unauthorizedMessage("Invalid Token", "Token does not exist")

  val noClaimNoMatchingToken =
    unauthorizedMessage("HAT claim unauthorized", "No user matching token")

  val noUserOrPass =
    unauthorizedMessage("Credentials required", "No username or password provided to retrieve token")

  val emailVerificationFailed =
    BadRequest(Json.toJson(ErrorMessage("Bad Request", "HAT email verification failed")))

  val iSEClaimFailed =
    InternalServerError(
      Json.toJson(ErrorMessage("Internal Server Error", "Failed to initialize HAT email verification process"))
    )

  // * Ok Responses *
  private def okMessage(body: String) = Ok(Json.toJson(SuccessResponse(s"${body}")))
  val hatIsAlreadyClaimed =
    okMessage("The email associated with this HAT has already been verified.")

  val resendVerificationEmail =
    okMessage(
      "If the email you have entered is correct and your HAT is not validated, you will receive an email with a link to validate your HAT."
    )

  def publicKey(): EssentialAction =
    indefiniteSuccessCaching {
      UserAwareAction.async { implicit request =>
        val publicKey =
          hatServerProvider.toString(request.dynamicEnvironment.publicKey)
        Future.successful(Ok(publicKey))
      }
    }

  // TODO: Should this remove tokens?
  def validateToken(): Action[AnyContent] =
    SecuredAction.async { _ =>
      Future.successful(Ok(Json.toJson(SuccessResponse("Authenticated"))))
    }

  def hatLogin(
      name: String,
      redirectUrl: String): Action[AnyContent] =
    SecuredAction(WithRole(Owner())).async { implicit request =>
      for {
        service <- hatServicesService.findOrCreateHatService(name, redirectUrl)
        linkedService <- hatServicesService.hatServiceLink(
                           request.identity,
                           service,
                           Some(redirectUrl)
                         )
        _ <- usersService.logLogin(
               request.identity,
               "hatLogin",
               linkedService.category,
               Some(name),
               Some(redirectUrl)
             )
      } yield Ok(Json.toJson(SuccessResponse(linkedService.url)))
    }

  def applicationToken(
      name: String,
      resource: String): Action[AnyContent] =
    SecuredAction(WithRole(Owner())).async { implicit request =>
      for {
        service <- hatServicesService.findOrCreateHatService(name, resource)
        token <- hatServicesService.hatServiceToken(request.identity, service)
      } yield Ok(Json.toJson(token))
    }

  // ???: this seems weird. :)
  private val hatService = HatService(
    "hat",
    "hat",
    "HAT API",
    "",
    "",
    "",
    browser = true,
    category = "api",
    setup = true,
    loginAvailable = true
  )

  // Trade username and password for an access_token
  def accessToken(): Action[AnyContent] =
    (UserAwareAction andThen limiter.UserAwareRateLimit).async { implicit request =>
      // pull details from the headers
      val eventuallyAuthenticatedUser = for {
        usernameParam <- request.headers.get("username")
        passwordParam <- request.headers.get("password")
      } yield {
        val username = URLDecoder.decode(usernameParam, "UTF-8")
        val password = URLDecoder.decode(passwordParam, "UTF-8")
        credentialsProvider
          .authenticate(Credentials(username, password))
          .map(_.copy(request.dynamicEnvironment.id))
          .flatMap { loginInfo =>
            usersService.getUser(loginInfo.providerKey).flatMap {
              // If we find a user, create and return an access token (JWT)
              case Some(user) =>
                val customClaims = hatServicesService.generateUserTokenClaims(user, hatService)
                for {
                  // JWT Authenticator
                  authenticator <- env.authenticatorService.create(loginInfo)
                  // JWT serialized as a String
                  token <- env.authenticatorService.init(
                             authenticator.copy(customClaims = Some(customClaims))
                           )
                  // Logging
                  _ <- usersService.logLogin(
                         user,
                         "api",
                         user.roles
                           .filter(_.extra.isEmpty)
                           .map(_.title)
                           .mkString(":"),
                         None,
                         None
                       )
                  // AuthenticatorResult
                  result <- env.authenticatorService.embed(
                              token,
                              Ok(Json.toJson(AccessToken(token, user.userId)))
                            )
                } yield {
                  // ???: Learn about the event bus
                  env.eventBus.publish(LoginEvent(user, request))
                  // AuthenticatorResult
                  result
                }
              // No user found
              case None =>
                Future.failed(new IdentityNotFoundException("Couldn't find user"))
            }
          }
      }
      // Credentials are no good --> Error
      eventuallyAuthenticatedUser getOrElse {
        Future.successful(noUserOrPass)
      }
    }

  /**
    * This is the authenticated, "I have the password, but I want to change it."
    */
  def passwordChangeProcess: Action[ApiPasswordChange] =
    SecuredAction(WithRole(Owner())).async(parsers.json[ApiPasswordChange]) { implicit request =>
      implicit val language: Lang = Lang.defaultLang
      logger.debug("Processing password change request")
      request.body.password map { oldPassword =>
        val eventualResult = for {
          _ <- credentialsProvider.authenticate(
                 Credentials(request.identity.email, oldPassword)
               )
          _ <- authInfoRepository.update(
                 request.identity.loginInfo,
                 passwordHasherRegistry.current.hash(request.body.newPassword)
               )
          authenticator <- env.authenticatorService.create(request.identity.loginInfo)
          result <- env.authenticatorService.renew(
                      authenticator,
                      Ok(Json.toJson(SuccessResponse("Password changed")))
                    )
        } yield {
          env.eventBus.publish(LoginEvent(request.identity, request))
          mailer.passwordChanged(request.identity.email)
          result
        }

        eventualResult recover {
          case _: InvalidPasswordException =>
            Forbidden(
              Json.toJson(
                ErrorMessage("Invalid password", "Old password invalid")
              )
            )
        }
      } getOrElse {
        Future.successful(
          Forbidden(
            Json.toJson(
              ErrorMessage("Invalid password", "Old password missing")
            )
          )
        )
      }
    }

  /**
    * Sends an email to the user with a link to reset the password
    * This is unauthenticated.
    */
  def handleForgotPassword: Action[ApiPasswordResetRequest] =
    UserAwareAction.async(parsers.json[ApiPasswordResetRequest]) { implicit request =>
      implicit val language: Lang = Lang.defaultLang
      logger.debug("Processing forgotten password request")
      val email = request.body.email
      val response = Ok(
        Json.toJson(
          SuccessResponse(
            "If the email you have entered is correct, you will shortly receive an email with password reset instructions"
          )
        )
      )
      if (email == request.dynamicEnvironment.ownerEmail)
        // Find the specific user who is the owner.
        usersService.listUsers
          .map(_.find(_.roles.contains(Owner())))
          .flatMap {
            case Some(_) =>
              // Create a token for the reset with a 24 hour expiry
              // isSignUp is potentially the issue here.
              val token = MailTokenUser(email, isSignup = false)
              // Store that token
              tokenService.create(token).map { _ =>
                mailer.passwordReset(email, passwordResetLink(request.host, token.id))
                response
              }
            // The user was not found, but return the "If we found an email address, we'll send the link."
            case None => Future.successful(response)
          }
      else
        Future.successful(response)
    }

  /**
    * Saves the new password and authenticates the user
    */
  def handleResetPassword(tokenId: String): Action[ApiPasswordChange] =
    UserAwareAction.async(parsers.json[ApiPasswordChange]) { implicit request =>
      implicit val language: Lang = Lang.defaultLang
      tokenService.retrieve(tokenId).flatMap {
        // Token was found, is not signup nor expired
        case Some(token) if !token.isSignUp && !token.isExpired =>
          // Token.email matches the dynamicEnv (what is this)
          if (token.email == request.dynamicEnvironment.ownerEmail)
            // Find the users with the owner role
            // ???: Why not using the email
            usersService.listUsers
              .map(_.find(_.roles.contains(Owner())))
              .flatMap {
                case Some(user) =>
                  for {
                    // ???: authInfoRepo
                    // Update with the new password info
                    _ <- authInfoRepository.update(
                           user.loginInfo,
                           passwordHasherRegistry.current
                             .hash(request.body.newPassword)
                         )
                    // ???: Get the authenticator - JWT maker
                    authenticator <- env.authenticatorService.create(user.loginInfo)
                    result <- env.authenticatorService.renew(
                                authenticator,
                                Ok(Json.toJson(SuccessResponse("Password reset")))
                              )
                  } yield {
                    // Delete the token
                    tokenService.consume(tokenId)
                    // ???: I must know more about the EventBus, for stats and logs
                    // Push a loginEvent on the bus
                    env.eventBus.publish(LoginEvent(user, request))
                    // Mail the user, telling them the password changed
                    mailer.passwordChanged(token.email)
                    // ???: return an AuthenticatorResult, why
                    result
                  }
                case None =>
                  Future.successful(noUserMatchingToken)
              }
          else
            Future.successful(onlyHatOwnerCanReset)
        case Some(_) =>
          tokenService.consume(tokenId)
          Future.successful(expiredToken)
        case None =>
          Future.successful(invalidToken)
      }
    }

  /**
    * Sends an email to the owner with a link to claim the hat
    * /control/v2/auth/claim
    */
  def handleVerificationRequest(lang: Option[String]): Action[ApiVerificationRequest] =
    UserAwareAction.async(parsers.json[ApiVerificationRequest]) { implicit request =>
      implicit val language: Lang = Lang.get(lang.getOrElse("en")).getOrElse(Lang.defaultLang)

      val claimHatRequest = request.body
      val email           = request.dynamicEnvironment.ownerEmail
      val response        = Ok(Json.toJson(SuccessResponse("You will shortly receive an email with claim instructions")))

      // (email, applicationId) in the body
      // Look up the application (Is this in the HAT itself?  Not DEX)
      if (claimHatRequest.email == email)
        usersService.listUsers
          .map(_.find(u => (u.roles.contains(Owner()) && !(u.roles.contains(Verified("email"))))))
          .flatMap {
            case Some(user) =>
              val eventualClaimContext = for {
                maybeApplication <- applicationsService
                                      .applicationStatus()(request.dynamicEnvironment, user, request)
                                      .map(_.find(_.application.id.equals(claimHatRequest.applicationId)))
                if maybeApplication.isDefined
                token <- ensureValidToken(email, isSignup = true)
              } yield (maybeApplication.get, token) // We only can reach this code if application is defined

              eventualClaimContext
                .map {
                  case (app, token) =>
                    val maybeSetupUrl: Option[String] = app.application.setup match {
                      case setupInfo: ApplicationSetup.External =>
                        setupInfo.validRedirectUris.find(_ == claimHatRequest.redirectUri)
                      case _ =>
                        None
                    }

                    if (maybeSetupUrl.isEmpty) {
                      val message =
                        s"Application [${claimHatRequest.applicationId}] mis-configured. \n Cause: ${claimHatRequest.redirectUri} is not a registered redirect URI"
                      logger.warn(message)
                      mailer.serverExceptionNotify(request, new RuntimeException(message))
                    }

                    val emailVerificationOptions =
                      EmailVerificationOptions(email, language, app.application.id, maybeSetupUrl.getOrElse(""))
                    val verificationLink = emailVerificationLink(request.host, token.id, emailVerificationOptions)
                    mailer.verifyEmail(email, verificationLink)

                    response
                }
                .recover {
                  case e =>
                    logger.error(s"Application ${claimHatRequest.applicationId} not available. Cause: $e")
                    BadRequest(
                      Json.toJson(
                        ErrorMessage("Bad request", s"Application ${claimHatRequest.applicationId} not available")
                      )
                    )
                }

            case None => Future.successful(response)
          }
      else
        Future.successful(response)
    }

  def handleVerification(verificationToken: String): Action[ApiVerificationCompletionRequest] =
    UserAwareAction.async(parsers.json[ApiVerificationCompletionRequest]) { implicit request =>
      implicit val hatClaimComplete: ApiVerificationCompletionRequest = request.body
      implicit val language: Lang                                     = Lang.defaultLang

      tokenService.retrieve(verificationToken).flatMap {
        case Some(token)
            if token.isSignUp && !token.isExpired && token.email == request.dynamicEnvironment.ownerEmail =>
          usersService.listUsers
            .map(_.find(u => (u.roles.contains(Owner()) && !(u.roles.contains(Verified("email"))))))
            .flatMap {
              case Some(user) =>
                val updatedUser = user.copy(roles = user.roles ++ Seq(Verified("email")))
                val eventualResult = for {
                  _ <- updateHatMembership(hatClaimComplete)
                  _ <- authInfoRepository.update(
                         updatedUser.loginInfo,
                         passwordHasherRegistry.current.hash(request.body.password)
                       )
                  _ <- tokenService.consume(token.id)
                  authenticator <- env.authenticatorService.create(updatedUser.loginInfo)
                  result <- env.authenticatorService.renew(
                              authenticator,
                              Ok(Json.toJson(SuccessResponse("HAT claimed")))
                            )

                } yield {
                  logService
                    .logAction(
                      request.dynamicEnvironment.domain,
                      LogRequest("claimed", None, None),
                      None
                    )
                    .recover {
                      case e =>
                        logger.error(
                          s"LogActionError::unclaimed. Reason: ${e.getMessage}"
                        )
                        Done
                    }

                  val fullyQualifiedHatAddress: String =
                    s"https://${hatClaimComplete.hatName}.${hatClaimComplete.hatCluster}"
                  mailer.emailVerified(token.email, fullyQualifiedHatAddress)
                  result
                }
                // ???: this is fishy
                //env.eventBus.publish(LoginEvent(user, request))

                eventualResult.recover {
                  case e =>
                    logger.error(s"HAT claim process failed with error ${e.getMessage}")
                    emailVerificationFailed
                }
              case None =>
                Future.successful(noClaimNoMatchingToken)
            }

        case Some(_) =>
          Future.successful(expiredToken)

        case None =>
          Future.successful(invalidToken)
      }
    }

  private def updateHatMembership(
      claim: ApiVerificationCompletionRequest): Future[Done] = {
    val hattersClaimPayload = HattersClaimPayload(claim, isSandboxPda)

    logger.info(s"Proxy POST request to ${pdaAccountRegistry.address} with parameters: $claim")

    // Tell Pda account registry this HAT is verified
    val futureResponse = wsClient
      .url(pdaAccountRegistry.address)
      //.withHttpHeaders("x-auth-token" -> token.accessToken)
      .post(Json.toJson(hattersClaimPayload))

    futureResponse.flatMap { response =>
      response.status match {
        case OK =>
          Future.successful(Done)
        case _ =>
          logger.error(
            s"Failed to claim HAT with Hatters. Claim details: $claim Hatters response: ${response.body}"
          )
          Future.failed(new UnknownError("HAT claim failed"))
      }
    }
  }

  /**
    * The function ensures there is a valid token to be returned to the client
    */

  private def ensureValidToken(
      email: String,
      isSignup: Boolean
    )(implicit hatServer: HatServer): Future[MailTokenUser] =
    tokenService.retrieve(email, isSignup).flatMap {
      case Some(token) if token.isExpired =>
        // TODO: log event for audit purpose
        for {
          _ <- tokenService.consume(token.id)
          newToken <- tokenService.create(MailTokenUser(email, isSignup = isSignup))
        } yield newToken.get // TODO: Using .get is not great here
      // the underlying implementation generates non-option type and then wraps it in Option, interface not great, suggestions appreciated
      case Some(token) =>
        Future.successful(token)
      case None =>
        // TODO: log event for audit purpose
        tokenService.create(MailTokenUser(email, isSignup = isSignup)).map(_.get)
    }

  /**
    * Generate email verification string
    */
  private def emailVerificationLink(
      host: String,
      token: String,
      verificationOptions: EmailVerificationOptions): String =
    s"$emailScheme$host/auth/verify-email/$token?${verificationOptions.asQueryParameters}"

  // TODO: add reset options support
  private def passwordResetLink(
      host: String,
      token: String): String =
    s"$emailScheme$host/auth/change-password/$token"

  // private def roleMatcher(rolesToMatch: Seq[UserRole], rolesRequired: Seq[UserRole]): Boolean = {
  //   //rolesToMatch.map(userRole => roleMatch(userRole, rolesRequired)
  //   false
  // }

  // private def roleMatch(roleToMatch: UserRole, rolesRequired: Seq[UserRole]): Boolean = {
  //   rolesRequired.map(roleRequired => )
  // }

  def roleMatchIt(
      roleToMatch: UserRole,
      roleRequired: UserRole): Boolean =
    roleRequired equals roleToMatch
  // roleToMatch match {
  //   case roleRequired: EmailVerified => true
  //   case _            => false
  // }
}
case class EmailVerificationOptions(
    email: String,
    language: Lang,
    applicationId: String,
    redirectUri: String) {

  lazy val asQueryParameters: String = {
    val encodedEmail = s"email=${URLEncoder.encode(email, "UTF-8")}"
    val lang         = s"lang=${language.language}"
    val application  = s"application_id=$applicationId"
    val redirect     = s"redirect_uri=$redirectUri"

    s"$encodedEmail&$lang&$application&$redirect"
  }
}
