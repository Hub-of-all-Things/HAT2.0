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

package org.hatdex.hat.resourceManagement

import java.io.{ StringReader, StringWriter }
import java.security.interfaces.{ RSAPrivateKey, RSAPublicKey }
import javax.inject.{ Inject, Singleton }

import scala.concurrent.{ ExecutionContext, Future }
import scala.util.Try

import com.atlassian.jwt.core.keys.KeyUtils
import org.bouncycastle.util.io.pem.{ PemObject, PemWriter }
import play.api.cache.AsyncCacheApi
import play.api.libs.ws.WSClient
import play.api.{ Configuration, Logger }

trait HatKeyProvider {
  protected val keyUtils = new KeyUtils()

  def publicKey(
      hat: String
    )(implicit ec: ExecutionContext): Future[RSAPublicKey]

  def privateKey(
      hat: String
    )(implicit ec: ExecutionContext): Future[RSAPrivateKey]

  def ownerEmail(hat: String)(implicit ec: ExecutionContext): Future[String]

  def toString(rsaPublicKey: RSAPublicKey): String = {
    val pemObject            = new PemObject("PUBLIC KEY", rsaPublicKey.getEncoded)
    val stringPemWriter      = new StringWriter()
    val pemWriter: PemWriter = new PemWriter(stringPemWriter)
    pemWriter.writeObject(pemObject)
    pemWriter.flush()
    val pemPublicKey = stringPemWriter.toString
    pemPublicKey
  }

  def issuer(hat: String) = hat

  protected def readRsaPublicKey(publicKey: String): Future[RSAPublicKey] = {
    val reader = new StringReader(publicKey)
    Try(keyUtils.readRsaPublicKeyFromPem(reader))
      .map(Future.successful)
      .recover {
        case e =>
          Future.failed(
            new HatServerDiscoveryException(s"Public Key reading failed", e)
          )
      }
      .get
  }

  protected def readRsaPrivateKey(privateKey: String): Future[RSAPrivateKey] = {
    val reader = new StringReader(privateKey)
    Try(keyUtils.readRsaPrivateKeyFromPem(reader))
      .map(Future.successful)
      .recover {
        case e =>
          Future.failed(
            new HatServerDiscoveryException(s"Private Key reading failed", e)
          )
      }
      .get
  }
}

@Singleton
class HatKeyProviderConfig @Inject() (configuration: Configuration) extends HatKeyProvider {
  def publicKey(
      hat: String
    )(implicit ec: ExecutionContext): Future[RSAPublicKey] =
    configuration.getOptional[String](
      s"hat.${hat.replace(':', '.')}.publicKey"
    ) map { confPublicKey =>
      readRsaPublicKey(confPublicKey)
    } getOrElse {
      Future.failed(
        new HatServerDiscoveryException(s"Public Key for $hat not found")
      )
    }

  def privateKey(
      hat: String
    )(implicit ec: ExecutionContext): Future[RSAPrivateKey] =
    configuration.getOptional[String](
      s"hat.${hat.replace(':', '.')}.privateKey"
    ) map { confPrivateKey =>
      readRsaPrivateKey(confPrivateKey)
    } getOrElse {
      Future.failed(
        new HatServerDiscoveryException(s"Private Key for $hat not found")
      )
    }

  def ownerEmail(hat: String)(implicit ec: ExecutionContext): Future[String] =
    configuration.getOptional[String](
      s"hat.${hat.replace(':', '.')}.ownerEmail"
    ) map { email =>
      Future.successful(email)
    } getOrElse {
      Future.failed(
        new HatServerDiscoveryException(s"Owner email for $hat not found")
      )
    }
}

@Singleton
class HatKeyProviderMilliner @Inject() (
    val configuration: Configuration,
    val cache: AsyncCacheApi,
    val ws: WSClient)
    extends HatKeyProvider
    with MillinerHatSignup {
  val logger: Logger = Logger(this.getClass)

  def publicKey(
      hat: String
    )(implicit ec: ExecutionContext): Future[RSAPublicKey] =
    getHatSignup(hat) flatMap { signup =>
      logger.debug(
        s"Received signup info, parsing public key ${signup.keys.map(_.publicKey)}"
      )
      readRsaPublicKey(signup.keys.get.publicKey)
    } recoverWith {
        case e =>
          Future.failed(
            new HatServerDiscoveryException(s"Public Key for $hat not found", e)
          )
      }

  def privateKey(
      hat: String
    )(implicit ec: ExecutionContext): Future[RSAPrivateKey] =
    getHatSignup(hat) flatMap { signup =>
      logger.debug(
        s"Received signup info, parsing private key ${signup.keys.map(_.privateKey)}"
      )
      readRsaPrivateKey(signup.keys.get.privateKey)
    } recoverWith {
        case _ =>
          Future.failed(
            new HatServerDiscoveryException(s"Private Key for $hat not found")
          )
      }

  def ownerEmail(hat: String)(implicit ec: ExecutionContext): Future[String] =
    getHatSignup(hat) map { signup =>
      signup.email
    } recoverWith {
        case _ =>
          Future.failed(
            new HatServerDiscoveryException(s"Owner email for $hat not found")
          )
      }
}
