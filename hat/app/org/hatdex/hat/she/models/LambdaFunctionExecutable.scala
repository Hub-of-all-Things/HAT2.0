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
 * 8 / 2018
 */

package org.hatdex.hat.she.models

import java.util.concurrent.ExecutorService

import akka.actor.ActorSystem
import akka.stream.{ ActorMaterializer, Materializer }
import akka.stream.alpakka.awslambda.scaladsl.AwsLambdaFlow
import akka.stream.scaladsl.{ Sink, Source }
import akka.util.ByteString
import com.amazonaws.auth.{ AWSStaticCredentialsProvider, BasicAWSCredentials }
import com.amazonaws.client.builder.ExecutorFactory
import com.amazonaws.services.lambda.model.{ InvokeRequest, InvokeResult }
import com.amazonaws.services.lambda.{ AWSLambdaAsync, AWSLambdaAsyncClientBuilder }
import javax.inject.Inject
import org.hatdex.dex.apiV2.services.Errors.{ ApiException, DataFormatException }
import org.hatdex.hat.api.models.EndpointDataBundle
import org.hatdex.hat.api.models.applications.Version
import org.hatdex.hat.api.service.RemoteExecutionContext
import org.hatdex.hat.utils.ExecutorServiceWrapper
import org.joda.time.DateTime
import play.api.{ Configuration, Logger }
import play.api.libs.json.{ Format, Json }

import scala.concurrent.{ ExecutionContext, Future }

class LambdaFunctionExecutable(
    id: String,
    version: Version,
    baseUrl: String,
    val namespace: String,
    val endpoint: String,
    val configuration: FunctionConfiguration
  )(config: Configuration,
    lambdaExecutor: AwsLambdaExecutor)
    extends FunctionExecutable {
  import FunctionConfigurationJsonProtocol._

  protected val logger: Logger = Logger(this.getClass)
  private val lambdaLogs       = config.get[String]("she.aws.logs")

  logger.debug(s"Initialised SHE lambda function $id v$version $baseUrl")

  def execute(
      configuration: FunctionConfiguration,
      requestData: Request): Future[Seq[Response]] = {
    val request = new InvokeRequest()
      .withFunctionName(s"$baseUrl-$id")
      .withLogType(lambdaLogs)
      .withPayload(
        Json
          .toJson(
            Map(
              "functionConfiguration" -> Json.toJson(configuration),
              "request" -> Json.toJson(requestData)
            )
          )
          .toString()
      )

    lambdaExecutor.execute[Seq[Response]](request)
  }

  override def bundleFilterByDate(
      fromDate: Option[DateTime],
      untilDate: Option[DateTime]): Future[EndpointDataBundle] = {
    val request = new InvokeRequest()
      .withFunctionName(s"$baseUrl-$id-bundle")
      .withLogType(lambdaLogs)
      .withPayload(
        Json
          .toJson(
            Map(
              "fromDate" -> fromDate.map(_.toString),
              "untilDate" -> untilDate.map(_.toString)
            )
          )
          .toString()
      )

    lambdaExecutor.execute[EndpointDataBundle](request)
  }
}

class LambdaFunctionLoader @Inject() (
    config: Configuration,
    lambdaExecutor: AwsLambdaExecutor) {

  import FunctionConfigurationJsonProtocol.functionConfigurationFormat

  protected val logger: Logger = Logger(this.getClass)
  private val lambdaLogs       = config.get[String]("she.aws.logs")

  def load(
      id: String,
      version: Version,
      baseUrl: String,
      namespace: String,
      endpoint: String
    )(implicit ec: ExecutionContext): Future[LambdaFunctionExecutable] = {
    val request = new InvokeRequest()
      .withFunctionName(s"$baseUrl-$id-configuration")
      .withLogType(lambdaLogs)
      .withPayload("\"\"")

    lambdaExecutor
      .execute[FunctionConfiguration](request)
      .map(c =>
        new LambdaFunctionExecutable(
          id,
          version,
          baseUrl,
          namespace,
          endpoint,
          c
        )(
          config,
          lambdaExecutor
        )
      )
  }
}

class AwsLambdaExecutor @Inject() (
    configuration: Configuration
  )(implicit
    val actorSystem: ActorSystem,
    ec: RemoteExecutionContext) {

  protected val logger: Logger = Logger(this.getClass)

  implicit private val materializer: Materializer = ActorMaterializer()

  private val credentials = new AWSStaticCredentialsProvider(
    new BasicAWSCredentials(
      configuration.get[String]("she.aws.accessKey"),
      configuration.get[String]("she.aws.secretKey")
    )
  )

  private val lambdaClient: AWSLambdaAsync =
    AWSLambdaAsyncClientBuilder
      .standard()
      .withRegion(configuration.get[String]("she.aws.region"))
      .withCredentials(credentials)
      .withExecutorFactory(new StaticExecutorFactory(ec))
      .build()

  def execute[T](
      request: InvokeRequest
    )(implicit jsonFormatter: Format[T]): Future[T] =
    Source
      .single(request)
      .via(AwsLambdaFlow(1)(lambdaClient))
      .runWith(Sink.head)
      .map {
        case r: InvokeResult if r.getStatusCode == 200 =>
          logger.debug(s"""Function responded with:
               | Status: ${r.getStatusCode}
               | Body: ${ByteString(r.getPayload).utf8String}
               | Logs: ${Option(r.getLogResult).map(l => ByteString(java.util.Base64.getDecoder.decode(l)).utf8String)}
            """.stripMargin)
          val jsResponse =
            Json.parse(r.getPayload.array()).validate[T] recover {
                case e =>
                  val message = s"Error parsing lambda response: $e"
                  logger.error(message)
                  throw DataFormatException(message)
              }
          jsResponse.get
        case r =>
          val message =
            s"Retrieving SHE function configuration failed: $r, ${ByteString(r.getPayload).utf8String}"
          logger.error(message)
          throw new ApiException(message)
      }
}

class StaticExecutorFactory(val ec: ExecutionContext) extends ExecutorFactory {
  override def newExecutor: ExecutorService = new ExecutorServiceWrapper()(ec)
}
