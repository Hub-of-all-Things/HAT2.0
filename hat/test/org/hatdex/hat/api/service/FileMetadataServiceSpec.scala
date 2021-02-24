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

import scala.concurrent.Await
import scala.concurrent.duration._

import io.dataswift.test.common.BaseSpec
import io.dataswift.models.hat.{ ApiHatFile, ApiHatFilePermissions, HatFileStatus }
import org.scalatest.{ BeforeAndAfterAll, BeforeAndAfterEach }
import play.api.Logger

class FileMetadataServiceSpec extends BaseSpec with BeforeAndAfterEach with BeforeAndAfterAll with FileManagerContext {
  import scala.concurrent.ExecutionContext.Implicits.global
  val logger = Logger(this.getClass)

  override def beforeAll: Unit =
    Await.result(databaseReady, 60.seconds)

  override protected def afterAll(): Unit =
    container.stop

  override def beforeEach: Unit = {
    import org.hatdex.hat.dal.Tables._
    import org.hatdex.libs.dal.HATPostgresProfile.api._

    val testFilesQuery = HatFile.filter(_.source.like("test%"))

    val action = DBIO.seq(HatFileAccess.filter(_.fileId in testFilesQuery.map(_.id)).delete, testFilesQuery.delete)

    Await.result(db.run(action), 60.seconds)
  }

  "The `getUniqueFileId` method" should "return a ApiHatFile with fileId appended" in {
    val service = application.injector.instanceOf[FileMetadataService]

    val fileWithId = service.getUniqueFileId(
      ApiHatFile(None, "testFile", "test", None, None, None, None, None, None, None, None, None)
    )

    val r = Await.result(fileWithId, 10.seconds)
    r.fileId.get === "testtestfile"
  }

  it should "keep file extension when creating file" in {
    val service = application.injector.instanceOf[FileMetadataService]

    val fileWithId = service.getUniqueFileId(
      ApiHatFile(None, "testFile.png", "test", None, None, None, None, None, None, None, None, None)
    )

    val r = Await.result(fileWithId, 10.seconds)
    r.fileId must not be empty
    r.fileId.get must equal("testtestfile.png")
  }

  it should "deduplicate file IDs by adding numbers to the end of the filename" in {
    val service = application.injector.instanceOf[FileMetadataService]

    val file = ApiHatFile(None,
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

    val fileWithId = for {
      first <- service.getUniqueFileId(file)
      _ <- service.save(first)
      second <- service.getUniqueFileId(file)
      _ <- service.save(second)
      third <- service.getUniqueFileId(file)
    } yield third

    val r = Await.result(fileWithId, 10.seconds)
    r.fileId must not be empty
    r.fileId.get must equal("testtestfile-2.png")
  }

  "The `save` method" should "insert new files into the database" in {
    val service = application.injector.instanceOf[FileMetadataService]
    val file = ApiHatFile(Some("testtestfile.png"),
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

    val saved = service.save(file)

    saved map { savedFile =>
      savedFile.dateCreated must not be empty
      savedFile.lastUpdated must not be empty
      savedFile.fileId must not be empty
    }
    Await.result(saved, 10.seconds)
  }

  it should "upsert file information for existing files" in {
    val service = application.injector.instanceOf[FileMetadataService]
    val file = ApiHatFile(Some("testtestfile.png"),
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

    val saved = service.save(file)

    saved flatMap { savedFile =>
      savedFile.dateCreated must not be empty
      savedFile.lastUpdated must not be empty
      savedFile.fileId must not be empty
      savedFile.fileId.get must equal("testtestfile.png")
      val updatedFile = savedFile.copy(tags = Some(Seq("testtag")))
      service.save(updatedFile)
    } map { savedFile =>
      savedFile.dateCreated must not be empty
      savedFile.fileId must not be empty
      savedFile.fileId.get must equal("testtestfile.png")
      savedFile.tags must not be empty
      savedFile.tags.get must contain("testtag")
    }
    Await.ready(saved, 10.seconds)
  }

  "The `delete` method" should "Change file status to `Deleted`" in {
    val service = application.injector.instanceOf[FileMetadataService]
    val file = ApiHatFile(Some("testtestfile.png"),
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
    val deleted = for {
      _ <- service.save(file)
      deleted <- service.delete("testtestfile.png")
    } yield deleted

    val r = Await.result(deleted, 10.seconds)
    r.status must equal(Some(HatFileStatus.Deleted()))
  }

  // it should "Throw error when deleting file that does not exist" in {
  //   val service = application.injector.instanceOf[FileMetadataService]

  //   databaseReady.flatMap { _ =>
  //     service.delete("testtestfile.png")
  //   } must throwA[Exception].await(3, 10.seconds)
  // }

  "The `getById` method" should "Return file information for an existing file" in {
    val service = application.injector.instanceOf[FileMetadataService]
    val file = ApiHatFile(Some("testtestfile.png"),
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

    val saved = service.save(file)

    saved flatMap { savedFile =>
      service.getById("testtestfile.png")
    } map { foundFile =>
      foundFile must not be empty
      foundFile.get.fileId === "testtestfile.png"
    }
    Await.result(saved, 10.seconds)
  }

  it should "Return `None` for file that does not exist" in {
    val service = application.injector.instanceOf[FileMetadataService]
    service.getById("testtestfile.png") === None
  }

  "The `search` method" should "Return empty list when no files exist" in {
    val service = application.injector.instanceOf[FileMetadataService]
    val found   = service.search(ApiHatFile(None, "", "", None, None, None, None, None, None, None, None, None))

    val r = Await.result(found, 10.seconds)
    r.length must equal(0)
  }

  it should "Look up a single file by Id" in {
    val service = application.injector.instanceOf[FileMetadataService]
    val found = for {
      _ <- service.save(
             ApiHatFile(Some("testtestfile.png"),
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
           )
      found <- service.search(
                 ApiHatFile(Some("testtestfile.png"), "", "", None, None, None, None, None, None, None, None, None)
               )
    } yield found

    val r = Await.result(found, 10.seconds)
    r.length must equal(1)
  }

  it should "Look up files by exact source" in {
    val service = application.injector.instanceOf[FileMetadataService]
    val found = for {
      _ <- service.save(
             ApiHatFile(Some("testtestfile.png"),
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
           )
      _ <- service.save(
             ApiHatFile(Some("testtestfile-1.png"),
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
           )
      _ <- service.save(
             ApiHatFile(Some("testtestfile-2.png"),
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
           )
      found <- service.search(ApiHatFile(None, "", "test", None, None, None, None, None, None, None, None, None))
    } yield found
    val r = Await.result(found, 10.seconds)
    r.length must equal(3)
  }

  it should "Look up files by exact name" in {
    val service = application.injector.instanceOf[FileMetadataService]
    val found = for {
      _ <- service.save(
             ApiHatFile(Some("testtestfile.png"),
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
           )
      _ <- service.save(
             ApiHatFile(Some("testtestfile-1.png"),
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
           )
      _ <- service.save(
             ApiHatFile(Some("testtestfile-2.png"),
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
           )
      found <-
        service.search(ApiHatFile(None, "testFile.png", "", None, None, None, None, None, None, None, None, None))
    } yield found

    val r = Await.result(found, 10.seconds)
    r.length must equal(3)

    val found2 = for {
      _ <- service.save(
             ApiHatFile(Some("testtestfile-3.png"),
                        "testFile3.png",
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
           )
      _ <- service.save(
             ApiHatFile(Some("testtestfile-4.png"),
                        "testFile4.png",
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
           )
      _ <- service.save(
             ApiHatFile(Some("testtestfile-5.png"),
                        "testFile5.png",
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
           )
      found <-
        service.search(ApiHatFile(None, "testFile3.png", "", None, None, None, None, None, None, None, None, None))
    } yield found

    val r2 = Await.result(found2, 10.seconds)
    r2.length must equal(1)
  }

  it should "Look up files by tags" in {
    val service = application.injector.instanceOf[FileMetadataService]
    val found = for {
      _ <- service.save(
             ApiHatFile(Some("testtestfile.png"),
                        "testFile.png",
                        "test",
                        None,
                        None,
                        Some(Seq("tag1")),
                        None,
                        None,
                        None,
                        Some(HatFileStatus.New()),
                        None,
                        None
             )
           )
      _ <- service.save(
             ApiHatFile(Some("testtestfile-1.png"),
                        "testFile1.png",
                        "test",
                        None,
                        None,
                        Some(Seq("tag1", "tag2")),
                        None,
                        None,
                        None,
                        Some(HatFileStatus.New()),
                        None,
                        None
             )
           )
      _ <- service.save(
             ApiHatFile(Some("testtestfile-2.png"),
                        "testFile2.png",
                        "test",
                        None,
                        None,
                        Some(Seq("tag1", "tag2", "tag3")),
                        None,
                        None,
                        None,
                        Some(HatFileStatus.New()),
                        None,
                        None
             )
           )
      foundT1 <-
        service.search(ApiHatFile(None, "", "", None, None, Some(Seq("tag1")), None, None, None, None, None, None))
      foundT12 <- service.search(
                    ApiHatFile(None, "", "", None, None, Some(Seq("tag1", "tag2")), None, None, None, None, None, None)
                  )
      foundT2 <-
        service.search(ApiHatFile(None, "", "", None, None, Some(Seq("tag2")), None, None, None, None, None, None))
      foundT123 <-
        service.search(
          ApiHatFile(None, "", "", None, None, Some(Seq("tag1", "tag2", "tag3")), None, None, None, None, None, None)
        )
      foundT3 <-
        service.search(ApiHatFile(None, "", "", None, None, Some(Seq("tag3")), None, None, None, None, None, None))
    } yield {
      foundT1.length must equal(3)
      foundT12.length must equal(2)
      foundT2.length must equal(2)
      foundT123.length must equal(1)
      foundT3.length must equal(1)
    }

    Await.result(found, 10.seconds)
  }

  it should "Look up files by status" in {
    val service = application.injector.instanceOf[FileMetadataService]
    val found = for {
      _ <- service.save(
             ApiHatFile(Some("testtestfile.png"),
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
           )
      _ <- service.save(
             ApiHatFile(Some("testtestfile-1.png"),
                        "testFile1.png",
                        "test",
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(HatFileStatus.Deleted()),
                        None,
                        None
             )
           )
      _ <- service.save(
             ApiHatFile(Some("testtestfile-2.png"),
                        "testFile2.png",
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
           )
      foundS1 <- service.search(
                   ApiHatFile(None, "", "", None, None, None, None, None, None, Some(HatFileStatus.New()), None, None)
                 )
      foundS2 <-
        service.search(
          ApiHatFile(None, "", "", None, None, None, None, None, None, Some(HatFileStatus.Deleted()), None, None)
        )
      foundS3 <-
        service.search(
          ApiHatFile(None, "", "", None, None, None, None, None, None, Some(HatFileStatus.Completed(0L)), None, None)
        )
    } yield {
      foundS1.length must equal(1)
      foundS2.length must equal(1)
      foundS3.length must equal(1)
    }

    Await.result(found, 10.seconds)
  }

  it should "Search files by description" in {
    val service = application.injector.instanceOf[FileMetadataService]
    val found = for {
      _ <- service.save(
             ApiHatFile(Some("testtestfile.png"),
                        "testFile.png",
                        "test",
                        None,
                        None,
                        None,
                        None,
                        Some("A rather short description"),
                        None,
                        Some(HatFileStatus.New()),
                        None,
                        None
             )
           )
      _ <- service.save(
             ApiHatFile(Some("testtestfile-1.png"),
                        "testFile1.png",
                        "test",
                        None,
                        None,
                        None,
                        None,
                        Some("A long description"),
                        None,
                        Some(HatFileStatus.New()),
                        None,
                        None
             )
           )
      _ <- service.save(
             ApiHatFile(
               Some("testtestfile-2.png"),
               "testFile2.png",
               "test",
               None,
               None,
               None,
               None,
               Some("A really long description than most people would use for their photos"),
               None,
               Some(HatFileStatus.New()),
               None,
               None
             )
           )
      foundT1 <- service.search(ApiHatFile(None, "", "", None, None, None, None, Some("long"), None, None, None, None))
      foundT2 <- service.search(ApiHatFile(None, "", "", None, None, None, None, Some("short"), None, None, None, None))
      foundT3 <- service.search(
                   ApiHatFile(None, "", "", None, None, None, None, Some("a description"), None, None, None, None)
                 )
    } yield {
      foundT1.length must equal(2)
      foundT2.length must equal(1)
      foundT3.length must equal(3)
    }

    Await.result(found, 10.seconds)
  }

  "The `grantAccess` method" should "Grant file detail access to an existing user" in {
    val service = application.injector.instanceOf[FileMetadataService]

    val granted = for {
      file <- service.save(
                ApiHatFile(Some("testtestfile.png"),
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
              )
      _ <- service.grantAccess(file, dataDebitUser, content = false)
      _ <- service.grantAccess(file, dataCreditUser, content = true)
      granted <- service.getById("testtestfile.png")
    } yield {
      granted must not be empty
      granted.get.contentPublic === false
      granted.get.permissions must not be empty
      granted.get.permissions.get.length must equal(2)
      granted.get.permissions.get must contain(ApiHatFilePermissions(dataDebitUser.userId, contentReadable = false))
      granted.get.permissions.get must contain(ApiHatFilePermissions(dataCreditUser.userId, contentReadable = true))
    }

    Await.result(granted, 10.seconds)
  }

  "The `restrictAccess` method" should "Restrict file access" in {
    val service = application.injector.instanceOf[FileMetadataService]

    val granted = for {
      file <- service.save(
                ApiHatFile(Some("testtestfile.png"),
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
              )
      _ <- service.grantAccess(file, dataCreditUser, content = false)
      _ <- service.grantAccess(file, dataDebitUser, content = true)
      _ <- service.restrictAccess(file, dataCreditUser)
      granted <- service.getById("testtestfile.png")
    } yield {
      granted must not be empty
      granted.get.contentPublic === false
      granted.get.permissions must not be empty
      granted.get.permissions.get.length must equal(1)
      granted.get.permissions.get must contain(ApiHatFilePermissions(dataDebitUser.userId, contentReadable = true))
    }

    Await.result(granted, 10.seconds)
  }

  "The `grantAccessPattern` method" should "Grant file access to an existing user for a matching file access pattern" in {
    val service = application.injector.instanceOf[FileMetadataService]

    val granted = for {
      file1 <- service.save(
                 ApiHatFile(Some("testtestfile-1.png"),
                            "testFile.png",
                            "test",
                            None,
                            None,
                            Some(Seq("tag1", "tag2")),
                            None,
                            None,
                            None,
                            Some(HatFileStatus.New()),
                            None,
                            None
                 )
               )
      file2 <- service.save(
                 ApiHatFile(Some("testtestfile-2.png"),
                            "testFile.png",
                            "test",
                            None,
                            None,
                            Some(Seq("tag1", "tag2")),
                            None,
                            None,
                            None,
                            Some(HatFileStatus.New()),
                            None,
                            None
                 )
               )
      file3 <- service.save(
                 ApiHatFile(Some("testtestfile-3.png"),
                            "testFile.png",
                            "test",
                            None,
                            None,
                            Some(Seq("tag1")),
                            None,
                            None,
                            None,
                            Some(HatFileStatus.New()),
                            None,
                            None
                 )
               )
      _ <- service.grantAccessPattern(
             ApiHatFile(None,
                        "testFile.png",
                        "test",
                        None,
                        None,
                        Some(Seq("tag1", "tag2")),
                        None,
                        None,
                        None,
                        Some(HatFileStatus.New()),
                        None,
                        None
             ),
             dataDebitUser,
             content = false
           )
      granted <- service.search(
                   ApiHatFile(None,
                              "testFile.png",
                              "test",
                              None,
                              None,
                              Some(Seq("tag1")),
                              None,
                              None,
                              None,
                              Some(HatFileStatus.New()),
                              None,
                              None
                   )
                 )
    } yield {
      granted.length must equal(3)

      val gfile1 = granted.find(_.fileId.contains("testtestfile-1.png"))
      gfile1 must not be empty
      gfile1.get.permissions.get.length must equal(1)
      gfile1.get.permissions.get must contain(ApiHatFilePermissions(dataDebitUser.userId, contentReadable = false))

      val gfile2 = granted.find(_.fileId.contains("testtestfile-2.png"))
      gfile2 must not be empty
      gfile2.get.permissions.get.length must equal(1)
      gfile2.get.permissions.get must contain(ApiHatFilePermissions(dataDebitUser.userId, contentReadable = false))

      val gfile3 = granted.find(_.fileId.contains("testtestfile-3.png"))
      gfile3 must not be empty
      gfile3.get.permissions.get.length must equal(0)
    }

    Await.result(granted, 10.seconds)
  }

  "The `restrictAccessPattern` method" should "Restrict file access to an existing user for a matching file access pattern" in {
    val service = application.injector.instanceOf[FileMetadataService]

    val granted = for {
      file1 <- service.save(
                 ApiHatFile(Some("testtestfile-1.png"),
                            "testFile.png",
                            "test",
                            None,
                            None,
                            Some(Seq("tag1", "tag2")),
                            None,
                            None,
                            None,
                            Some(HatFileStatus.New()),
                            None,
                            None
                 )
               )
      file2 <- service.save(
                 ApiHatFile(Some("testtestfile-2.png"),
                            "testFile.png",
                            "test",
                            None,
                            None,
                            Some(Seq("tag1", "tag2")),
                            None,
                            None,
                            None,
                            Some(HatFileStatus.New()),
                            None,
                            None
                 )
               )
      file3 <- service.save(
                 ApiHatFile(Some("testtestfile-3.png"),
                            "testFile.png",
                            "test",
                            None,
                            None,
                            Some(Seq("tag1")),
                            None,
                            None,
                            None,
                            Some(HatFileStatus.New()),
                            None,
                            None
                 )
               )
      _ <- service.grantAccessPattern(ApiHatFile(None,
                                                 "testFile.png",
                                                 "test",
                                                 None,
                                                 None,
                                                 Some(Seq("tag1")),
                                                 None,
                                                 None,
                                                 None,
                                                 Some(HatFileStatus.New()),
                                                 None,
                                                 None
                                      ),
                                      dataDebitUser,
                                      content = false
           )
      _ <- service.restrictAccessPattern(ApiHatFile(None,
                                                    "testFile.png",
                                                    "test",
                                                    None,
                                                    None,
                                                    Some(Seq("tag1", "tag2")),
                                                    None,
                                                    None,
                                                    None,
                                                    Some(HatFileStatus.New()),
                                                    None,
                                                    None
                                         ),
                                         dataDebitUser
           )
      granted <- service.search(
                   ApiHatFile(None,
                              "testFile.png",
                              "test",
                              None,
                              None,
                              Some(Seq("tag1")),
                              None,
                              None,
                              None,
                              Some(HatFileStatus.New()),
                              None,
                              None
                   )
                 )
    } yield {
      granted.length must equal(3)

      val gfile1 = granted.find(_.fileId.contains("testtestfile-1.png"))
      gfile1 must not be empty
      gfile1.get.permissions.get.length must equal(0)

      val gfile2 = granted.find(_.fileId.contains("testtestfile-2.png"))
      gfile2 must not be empty
      gfile2.get.permissions.get.length must equal(0)

      val gfile3 = granted.find(_.fileId.contains("testtestfile-3.png"))
      gfile3 must not be empty
      gfile3.get.permissions.get.length must equal(1)
      gfile3.get.permissions.get must contain(ApiHatFilePermissions(dataDebitUser.userId, contentReadable = false))
    }

    Await.result(granted, 10.seconds)
  }

}
