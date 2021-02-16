// /*
//  * Copyright (C) 2017 HAT Data Exchange Ltd
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
//  * Written by Andrius Aucinas <andrius.aucinas@hatdex.org>
//  * 2 / 2017
//  */

// package org.hatdex.hat.api.service

// import org.hatdex.hat.api.HATTestContext
// import org.specs2.concurrent.ExecutionEnv
// import org.specs2.mock.Mockito
// import play.api.Logger
// import play.api.test.PlaySpecification

// import scala.concurrent.Future
// import scala.concurrent.duration._

// class FileManagerS3Spec(implicit ee: ExecutionEnv) extends PlaySpecification /* with Mockito*/ with FileManagerContext {

//   val logger = Logger(this.getClass)

//   sequential

//   "The `getUploadUrl` method" should {
//     "return a signed url for a provided key" in {
//       val fileManager            = application.injector.instanceOf[FileManager]
//       val result: Future[String] = fileManager.getUploadUrl("testFile", None)

//       result must startWith("https://hat-storage-test.s3.eu-west-1.amazonaws.com/hat.hubofallthings.net/testFile").await
//     }
//   }

//   "The `getContentUrl` method" should {
//     "return a signed url for a provided key" in {
//       val fileManager            = application.injector.instanceOf[FileManager]
//       val result: Future[String] = fileManager.getContentUrl("testFile")

//       result must startWith("https://hat-storage-test.s3.eu-west-1.amazonaws.com/hat.hubofallthings.net/testFile").await
//     }
//   }

//   "The `deleteContents` method" should {
//     "return quietly when deleting any file" in {
//       val fileManager          = application.injector.instanceOf[FileManager]
//       val result: Future[Unit] = fileManager.deleteContents("deleteFile")

//       result must not(throwAn[Exception]).await
//       there was one(mockS3client).deleteObject("hat-storage-test", "hat.hubofallthings.net/deleteFile")
//     }
//   }

//   "The `getFileSize` method" should {
//     "return 0 for files that do not exist" in {
//       val fileManager          = application.injector.instanceOf[FileManager]
//       val result: Future[Long] = fileManager.getFileSize("nonExistentFile")

//       result must equalTo(0L).await(3, 10.seconds)
//     }

//     "extract file size for files that do exist" in {
//       val fileManager          = application.injector.instanceOf[FileManager]
//       val result: Future[Long] = fileManager.getFileSize("testFile")

//       result must equalTo(123456L).await
//       there was one(mockS3client).getObjectMetadata("hat-storage-test", "hat.hubofallthings.net/testFile")
//     }
//   }
// }

// trait FileManagerContext extends HATTestContext {
//   val mockS3client = fileManagerS3Mock.mockS3client
// }
