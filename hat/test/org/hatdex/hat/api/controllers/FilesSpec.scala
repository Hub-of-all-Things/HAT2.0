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

package org.hatdex.hat.api.controllers

import com.mohiva.play.silhouette.api.LoginInfo
import com.mohiva.play.silhouette.test._
import org.hatdex.hat.api.HATTestContext
import org.hatdex.hat.api.models._
import org.hatdex.hat.api.service._
import play.api.Logger
import play.api.libs.json.Json
import play.api.mvc.Result
import play.api.test.{ FakeRequest, Helpers }

import scala.concurrent.duration._
import scala.concurrent.{ Await, Future }
import io.dataswift.test.common.BaseSpec
import org.scalatest.{ BeforeAndAfterAll, BeforeAndAfterEach }
import play.api.test.Helpers
import play.api.test.Helpers._

class FilesSpec extends BaseSpec with BeforeAndAfterEach with BeforeAndAfterAll with FilesContext {
  import scala.concurrent.ExecutionContext.Implicits.global

  val logger = Logger(this.getClass)

  import org.hatdex.hat.api.json.HatJsonFormats._

  override def beforeAll: Unit =
    Await.result(databaseReady, 60.seconds)

  override def afterAll() =
    container.stop()

  override def beforeEach: Unit = {
    import org.hatdex.hat.dal.Tables._
    import org.hatdex.libs.dal.HATPostgresProfile.api._

    val action = DBIO.seq(
      HatFileAccess.delete,
      HatFile.delete
    )

    Await.result(db.run(action), 60.seconds)
  }

  "The `startUpload` method" should "return status 401 if authenticator but no identity was found" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(LoginInfo("xing", "comedian@watchmen.com"))
      .withJsonBody(Json.toJson(hatFileSimple))

    val controller             = application.injector.instanceOf[Files]
    val result: Future[Result] = Helpers.call(controller.startUpload, request)

    status(result) must equal(UNAUTHORIZED)
  }

  it should "return status 403 if authenticator and existing identity but wrong role" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(dataDebitUser.loginInfo)
      .withJsonBody(Json.toJson(hatFileSimple))

    val controller             = application.injector.instanceOf[Files]
    val result: Future[Result] = Helpers.call(controller.startUpload, request)

    status(result) must equal(FORBIDDEN)
  }

  it should "return accepted file details if authenticator for matching `dataCredit` identity" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(dataCreditUser.loginInfo)
      .withJsonBody(Json.toJson(hatFileSimple))

    val controller             = application.injector.instanceOf[Files]
    val result: Future[Result] = Helpers.call(controller.startUpload, request)

    status(result) must equal(OK)
    val file = contentAsJson(result).as[ApiHatFile]
    file.fileId must not be empty
    file.contentPublic === false
    file.dateCreated must not be empty
    file.lastUpdated must not be empty
    file.contentUrl must not be empty
    file.permissions must not be empty
    file.status === (HatFileStatus.New())
    file.permissions.get must contain(ApiHatFilePermissions(dataCreditUser.userId, contentReadable = true))
  }

  "The `completeUpload` method" should "return status 404 if no such file exists" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller             = application.injector.instanceOf[Files]
    val result: Future[Result] = controller.completeUpload("testFile.png").apply(request)

    status(result) must equal(NOT_FOUND)
    (contentAsJson(result) \ "message").as[String] must equal("No such file")
  }

  it should "return status 404 if user has no permission to get file contents" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(dataCreditUser.loginInfo)

    val controller = application.injector.instanceOf[Files]

    val result: Future[Result] = controller.completeUpload("testFile.png").apply(request)

    status(result) must equal(NOT_FOUND)
    (contentAsJson(result) \ "message").as[String] must equal("No such file")
  }

  it should "return status 400 if file incomplete" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller          = application.injector.instanceOf[Files]
    val fileMetadataService = application.injector.instanceOf[FileMetadataService]

    val result: Future[Result] = for {
      _ <- fileMetadataService.save(hatFileSimplePng)
      result <- controller.completeUpload("testtestFile.png").apply(request)
    } yield result

    status(result) must equal(BAD_REQUEST)
    (contentAsJson(result) \ "message").as[String] must equal("File not available")
  }

  it should "mark file completed when it is successfully uploaded" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller          = application.injector.instanceOf[Files]
    val fileMetadataService = application.injector.instanceOf[FileMetadataService]

    val result = for {
      saveResult <- fileMetadataService.save(hatFileSimple)
      result <- controller.completeUpload("testFile").apply(request)
    } yield result

    // val r = Await.result(result, 10.seconds)
    // r._1.header.status must equal(OK)

    status(result) must equal(OK)
    val file = contentAsJson(result).as[ApiHatFile]
    file.status === (HatFileStatus.Completed(123456L))
  }

  "The `getDetail` method" should "return status 401 if authenticator but no identity was found" in {
    val request = FakeRequest("POST", "http://hat.hubofallthings.net")
      .withAuthenticator(LoginInfo("xing", "comedian@watchmen.com"))

    val controller             = application.injector.instanceOf[Files]
    val result: Future[Result] = databaseReady.flatMap(_ => controller.getDetail("testFile.png").apply(request))

    status(result) must equal(UNAUTHORIZED)
  }

  it should "return status 404 if authenticator for matching identity but no such file exists" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller             = application.injector.instanceOf[Files]
    val result: Future[Result] = databaseReady.flatMap(_ => controller.getDetail("testFile.png").apply(request))

    status(result) must equal(NOT_FOUND)
    (contentAsJson(result) \ "message").as[String] must equal("No such file")
  }

  it should "return status 404 if file exists but user is not allowed access" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(dataCreditUser.loginInfo)

    val controller          = application.injector.instanceOf[Files]
    val fileMetadataService = application.injector.instanceOf[FileMetadataService]

    val result: Future[Result] = for {
      _ <- fileMetadataService.save(hatFileSimple)
      result <- controller.getDetail(hatFileSimple.fileId.get).apply(request)
    } yield result

    status(result) must equal(NOT_FOUND)
    (contentAsJson(result) \ "message").as[String] must equal("File not available")
  }

  it should "return file details but no content URL for allowed user" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(dataCreditUser.loginInfo)

    val controller          = application.injector.instanceOf[Files]
    val fileMetadataService = application.injector.instanceOf[FileMetadataService]

    val result: Future[Result] = for {
      _ <- fileMetadataService.save(hatFileSimpleComplete)
      _ <- fileMetadataService.grantAccess(hatFileSimple, dataCreditUser, content = false)
      result <- controller.getDetail(hatFileSimple.fileId.get).apply(request)
    } yield result

    status(result) must equal(OK)
    val file = contentAsJson(result).as[ApiHatFile]
    file.status === (HatFileStatus.Completed(123456L))
    file.permissions must equal(None)
    file.contentUrl must equal(None)
  }

  it should "return file details and content URL for allowed user" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(dataCreditUser.loginInfo)

    val controller          = application.injector.instanceOf[Files]
    val fileMetadataService = application.injector.instanceOf[FileMetadataService]

    val result: Future[Result] = for {
      _ <- fileMetadataService.save(hatFileSimpleComplete)
      _ <- fileMetadataService.grantAccess(hatFileSimple, dataCreditUser, content = true)
      result <- controller.getDetail(hatFileSimple.fileId.get).apply(request)
    } yield result

    status(result) must equal(OK)
    val file = contentAsJson(result).as[ApiHatFile]
    file.status === (HatFileStatus.Completed(123456L))
    file.permissions must equal(None)
    file.contentUrl must not be empty
  }

  "The `getContent` method" should "Return 404 for files that do not exist" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")

    val controller = application.injector.instanceOf[Files]

    val result: Future[Result] = controller.getContent(hatFileSimple.fileId.get).apply(request)

    status(result) must equal(NOT_FOUND)
    contentAsString(result) must equal("")
  }

  it should "Return 404 for files that user is not allowed to read content of" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(dataCreditUser.loginInfo)

    val controller          = application.injector.instanceOf[Files]
    val fileMetadataService = application.injector.instanceOf[FileMetadataService]

    val result: Future[Result] = for {
      _ <- fileMetadataService.save(hatFileSimpleComplete)
      _ <- fileMetadataService.grantAccess(hatFileSimple, dataCreditUser, content = false)
      result <- controller.getContent(hatFileSimple.fileId.get).apply(request)
    } yield result

    status(result) must equal(NOT_FOUND)
    contentAsString(result) must equal("")
  }

  it should "Redirect to file url for publicly readable files" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")

    val controller          = application.injector.instanceOf[Files]
    val fileMetadataService = application.injector.instanceOf[FileMetadataService]

    val result: Future[Result] = for {
      _ <- fileMetadataService.save(hatFileSimpleCompletePublic)
      result <- controller.getContent(hatFileSimpleCompletePublic.fileId.get).apply(request)
    } yield result

    result map { response =>
      logger.debug(s"GET content response:  $response")
    }

    redirectLocation(result) must not be empty
    redirectLocation(result).get must startWith(
      "https://hat-storage-test.s3.eu-west-1.amazonaws.com/hat.hubofallthings.net/testFile"
    )
  }

  it should "Redirect to file url for permitted files files" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(dataCreditUser.loginInfo)

    val controller          = application.injector.instanceOf[Files]
    val fileMetadataService = application.injector.instanceOf[FileMetadataService]

    val result: Future[Result] = for {
      _ <- fileMetadataService.save(hatFileSimpleComplete)
      _ <- fileMetadataService.grantAccess(hatFileSimpleComplete, dataCreditUser, content = true)
      result <- controller.getContent(hatFileSimpleComplete.fileId.get).apply(request)
    } yield result

    redirectLocation(result) must not be empty
    redirectLocation(result).get must startWith(
      "https://hat-storage-test.s3.eu-west-1.amazonaws.com/hat.hubofallthings.net/testFile"
    )
  }

  "The `changePublicAccess` method" should "Let `owner` user make file publicly accessible" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller          = application.injector.instanceOf[Files]
    val fileMetadataService = application.injector.instanceOf[FileMetadataService]

    val result: Future[Result] = for {
      file <- fileMetadataService.save(hatFileSimpleComplete)
      result <- controller.changePublicAccess(file.fileId.get, public = true).apply(request)
    } yield result

    val file = contentAsJson(result).as[ApiHatFile]
    file.contentPublic === true
  }

  it should "Let `owner` user restrict file publicly accessibility" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(owner.loginInfo)

    val controller          = application.injector.instanceOf[Files]
    val fileMetadataService = application.injector.instanceOf[FileMetadataService]

    val result: Future[Result] = for {
      file <- fileMetadataService.save(hatFileSimpleCompletePublic)
      result <- controller.changePublicAccess(file.fileId.get, public = false).apply(request)
    } yield result

    val file = contentAsJson(result).as[ApiHatFile]
    file.contentPublic === false
  }

  it should "Return 401 for not `owner` user making file publicly accessible" in {
    val request = FakeRequest("GET", "http://hat.hubofallthings.net")
      .withAuthenticator(dataCreditUser.loginInfo)

    val controller          = application.injector.instanceOf[Files]
    val fileMetadataService = application.injector.instanceOf[FileMetadataService]

    val result: Future[Result] = for {
      file <- fileMetadataService.save(hatFileSimpleComplete)
      result <- controller.changePublicAccess(file.fileId.get, public = true).apply(request)
    } yield result

    status(result) must equal(FORBIDDEN)
  }
}

trait FilesContext extends HATTestContext {
  val hatFileSimple = ApiHatFile(Some("testFile"),
                                 "testFile",
                                 "test",
                                 None,
                                 None,
                                 None,
                                 None,
                                 None,
                                 None,
                                 Some(HatFileStatus.New()),
                                 None,
                                 None
  )
  val hatFileSimpleComplete = ApiHatFile(Some("testFile"),
                                         "testFile",
                                         "test",
                                         None,
                                         None,
                                         None,
                                         None,
                                         None,
                                         None,
                                         Some(HatFileStatus.Completed(123456L)),
                                         None,
                                         None
  )
  val hatFileSimpleCompletePublic = ApiHatFile(Some("testFile"),
                                               "testFile",
                                               "test",
                                               None,
                                               None,
                                               None,
                                               None,
                                               None,
                                               None,
                                               Some(HatFileStatus.Completed(123456L)),
                                               None,
                                               None,
                                               Some(true)
  )
  val hatFileSimplePng = ApiHatFile(Some("testtestFile.png"),
                                    "testFile.png",
                                    "test",
                                    None,
                                    None,
                                    None,
                                    None,
                                    None,
                                    None,
                                    Some(HatFileStatus.New()),
                                    None,
                                    None
  )
}
