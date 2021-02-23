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

import com.amazonaws.auth.{ AWSStaticCredentialsProvider, BasicAWSCredentials }
import com.amazonaws.services.s3.model.ObjectMetadata
import com.amazonaws.services.s3.{ AmazonS3, AmazonS3ClientBuilder }
import org.scalatestplus.mockito._
import org.mockito.Mockito._

import scala.concurrent.duration._

case class FileManagerS3Mock() extends MockitoSugar {
  val s3Configuration =
    AwsS3Configuration("hat-storage-test", "testAwsAccessKey", "testAwsSecret", "eu-west-1", 5.minutes)
  private val awsCreds: BasicAWSCredentials =
    new BasicAWSCredentials(s3Configuration.accessKeyId, s3Configuration.secretKey)
  val mockS3client: AmazonS3 =
    AmazonS3ClientBuilder
      .standard()
      .withRegion("eu-west-1")
      .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
      .build()

  private val s3ObjectMetadata = new ObjectMetadata()
  s3ObjectMetadata
    .setContentLength(123456L)
  when(mockS3client.getObjectMetadata("hat-storage-test", "hat.hubofallthings.net/testFile"))
    .thenReturn(s3ObjectMetadata)
  when(mockS3client.deleteObject("hat-storage-test", "hat.hubofallthings.net/deleteFile")).thenReturn(())
}
