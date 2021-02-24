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
 * 2 / 2017
 */

package org.hatdex.hat.resourceManagement.actors

import javax.inject.Inject

import scala.collection.mutable
import scala.concurrent.Future
import scala.concurrent.duration._
import scala.util.{ Failure, Success }

import akka.actor.{ Props, _ }
import akka.util.Timeout
import org.hatdex.hat.api.service.RemoteExecutionContext
import org.hatdex.hat.utils.ActiveHatCounter
import play.api.libs.concurrent.InjectedActorSupport
import play.api.{ Configuration, Logger }

class HatServerProviderActor @Inject() (
    hatServerActorFactory: HatServerActor.Factory,
    activeHatcounter: ActiveHatCounter,
    configuration: Configuration
  )(implicit
    val ec: RemoteExecutionContext)
    extends Actor
    with InjectedActorSupport {
  private val log = Logger(this.getClass)
  import HatServerProviderActor._

  private val activeServers = mutable.HashMap[String, ActorRef]()
  implicit private val hatServerTimeout: Timeout =
    configuration.get[FiniteDuration](
      "resourceManagement.serverProvisioningTimeout"
    )

  def receive: Receive = {
    case HatServerRetrieve(hat) =>
      log.info(s"Retrieve HAT server $hat for $sender")
      val retrievingSender = sender
      getHatServerActor(hat) map { hatServerActor =>
        log.info(
          s"Success: Got HAT server provider actor, forwarding retrieval message with sender $sender $retrievingSender"
        )
        hatServerActor tell (HatServerActor.HatRetrieve(), retrievingSender)
      } onComplete {
        case Success(_) => ()
        case Failure(e) =>
          log.warn(
            s"Failure: Error while getting HAT server provider actor: ${e.getMessage}"
          )
      }

    case HatServerStarted(_) =>
      activeHatcounter.increase()

    case HatServerStopped(_) =>
      activeHatcounter.decrease()

    case message =>
      log.warn(s"Received unexpected message $message")
  }

  private def getHatServerActor(hat: String): Future[ActorRef] =
    doFindOrCreate(hat, hatServerTimeout.duration / 4)

  private val maxAttempts = 3
  private def doFindOrCreate(
      hat: String,
      timeout: FiniteDuration,
      depth: Int = 0): Future[ActorRef] = {
    if (depth >= maxAttempts) {
      log.error(s"HAT server actor for $hat not resolved")
      throw new RuntimeException(
        s"Can not create actor for $hat and reached max attempts of $maxAttempts"
      )
    }

    val selection = s"/user/hatServerProviderActor/hat:$hat"
    log.info(s"ActorSelection: ${selection}")

    context.actorSelection(selection).resolveOne(timeout) map { hatServerActor =>
      log.info(s"HAT server actor $selection resolved")
      hatServerActor
    } recoverWith {
      case ActorNotFound(_) =>
        log.warn(s"HAT server actor ($selection) not found, injecting child")
        val hatServerActor = injectedChild(
          hatServerActorFactory(hat),
          s"hat:$hat",
          props = (props: Props) => props.withDispatcher("hat-server-provider-actor-dispatcher")
        )
        activeServers(hat) = hatServerActor
        log.warn(s"Injected actor $hatServerActor")
        doFindOrCreate(hat, timeout, depth + 1)
    }
  }

}

object HatServerProviderActor {
  case class HatServerRetrieve(hat: String)

  case class HatServerStarted(hat: String)
  case class HatServerStopped(hat: String)
}
