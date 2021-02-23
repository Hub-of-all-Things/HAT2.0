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

package org.hatdex.hat.api.service

import org.hatdex.hat.api.HATTestContext
import play.api.Logger

import scala.concurrent.{ Await, Future }
import scala.concurrent.duration._
import io.dataswift.test.common.BaseSpec
import org.scalatest.{ BeforeAndAfterAll, BeforeAndAfterEach }

class FileManagerS3Spec extends BaseSpec with BeforeAndAfterEach with BeforeAndAfterAll with FileManagerContext {

  val logger = Logger(this.getClass)

  "The `getUploadUrl` method" should "return a signed url for a provided key" in {
    val fileManager            = application.injector.instanceOf[FileManager]
    val result: Future[String] = fileManager.getUploadUrl("testFile", None)

    val r = Await.result(result, 10.seconds)
    r must startWith("https://hat-storage-test.s3.eu-west-1.amazonaws.com/hat.hubofallthings.net/testFile")
  }

  "The `getContentUrl` method" should "return a signed url for a provided key" in {
    val fileManager            = application.injector.instanceOf[FileManager]
    val result: Future[String] = fileManager.getContentUrl("testFile")

    val r = Await.result(result, 10.seconds)
    r must startWith("https://hat-storage-test.s3.eu-west-1.amazonaws.com/hat.hubofallthings.net/testFile")
  }

  "The `deleteContents` method" should "return quietly when deleting any file" in {
    val fileManager = application.injector.instanceOf[FileManager]
    //val result: Future[Unit] = fileManager.deleteContents("deleteFile")
    //val r = Await.result(result, 10.seconds)

    try fileManager.deleteContents("deleteFile")
    catch {
      case (e: Exception) =>
        logger.info("This should not throw an exception.")
        fail
      case _ =>
        // CalledMatchers are part of specs2
        //there was one(mockS3client).deleteObject("hat-storage-test", "hat.hubofallthings.net/deleteFile")
        true
    }
  }

  "The `getFileSize` method" should "return 0 for files that do not exist" in {
    val fileManager          = application.injector.instanceOf[FileManager]
    val result: Future[Long] = fileManager.getFileSize("nonExistentFile")

    val r = Await.result(result, 10.seconds)
    r must equal(0L)
  }

  it should "extract file size for files that do exist" in {
    val fileManager          = application.injector.instanceOf[FileManager]
    val result: Future[Long] = fileManager.getFileSize("testFile")

    val r = Await.result(result, 10.seconds)
    println(r)
    r must equal(123456L)
    // CalledMatchers are part of specs2
    //there was one(mockS3client).getObjectMetadata("hat-storage-test", "hat.hubofallthings.net/testFile")
  }
}

trait FileManagerContext extends HATTestContext {
  val mockS3client = fileManagerS3Mock.mockS3client
}
