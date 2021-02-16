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

// import org.hatdex.hat.api.models.{ ApiHatFile, ApiHatFilePermissions, HatFileStatus }
// import org.specs2.concurrent.ExecutionEnv
// import org.specs2.mock.Mockito
// import org.specs2.specification.{ BeforeAll, BeforeEach }
// import play.api.Logger
// import play.api.test.PlaySpecification

// import org.hatdex.libs.dal.HATPostgresProfile.backend.Database

// import org.scalatest._
// import matchers.should._
// import flatspec._
// import com.dimafeng.testcontainers.{ ForAllTestContainer, PostgreSQLContainer }

// import scala.concurrent.Await
// import scala.concurrent.duration._
// import play.api.Configuration
// import org.hatdex.hat.resourceManagement.{ FakeHatConfiguration, HatServer }
// import scala.concurrent.{ Await, Future }
// import com.atlassian.jwt.core.keys.KeyUtils
// import java.io.StringReader
// import play.api.inject.guice.GuiceApplicationBuilder
// import play.api.{ Logger, Application => PlayApplication }
// import org.hatdex.hat.helpers.{ ContainerUtils }
// import org.hatdex.hat.authentication.models.HatUser
// import scala.util.Random

// import scala.concurrent.Await
// import scala.concurrent.duration._

// class FileMetadataServiceSpec
//     extends AnyFlatSpec
//     with Matchers
//     with FileManagerContext
//     with ContainerUtils
//     with ForAllTestContainer {

// //class FileMetadataServiceSpec(implicit ee: ExecutionEnv) extends PlaySpecification with Mockito with FileManagerContext with BeforeEach with BeforeAll {

//   // Ephemeral PG Container for this test suite
//   override val container = PostgreSQLContainer()
//   container.start()

//   override val hatAddress   = "hat.hubofallthings.net"
//   val logger                = Logger(this.getClass)
//   private val configuration = Configuration.from(FakeHatConfiguration.config)
//   private val keyUtils      = new KeyUtils()
//   private val hatConfig     = configuration.get[Configuration](s"hat.$hatAddress")
//   implicit override lazy val application: PlayApplication = new GuiceApplicationBuilder()
//     .configure(FakeHatConfiguration.config)
//     .build()

//   implicit val db: Database = Database.forURL(
//     url = container.jdbcUrl,
//     user = container.username,
//     password = container.password
//   )

//   override val owner = new HatUser(userId = java.util.UUID.randomUUID(),
//                                    email = "hat@example.com",
//                                    pass = None,
//                                    name = "hat",
//                                    roles = Seq.empty,
//                                    enabled = true
//   )

//   implicit override val hatServer: HatServer = HatServer(
//     hatAddress,
//     "hat",
//     "user@hat.org",
//     keyUtils.readRsaPrivateKeyFromPem(new StringReader(hatConfig.get[String]("privateKey"))),
//     keyUtils.readRsaPublicKeyFromPem(new StringReader(hatConfig.get[String]("publicKey"))),
//     db
//   )

//   import scala.concurrent.ExecutionContext.Implicits.global

//   val conf = containerToConfig(container)

//   Await.result(databaseReady(db, conf), 60.seconds)

//   "The `getUniqueFileId` method" should "return a ApiHatFile with fileId appended" in {
//     val service = application.injector.instanceOf[FileMetadataService]

//     val fileWithId = service.getUniqueFileId(
//       ApiHatFile(None, "testFile", "test", None, None, None, None, None, None, None, None, None)
//     )

//     val f = Await.result(fileWithId, 10.seconds)
//     f.fileId should be('defined)
//     f.fileId.get should equal("testtestfile")
//   }

//   // it should  "keep file extension when creating file" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]

//   //     val fileWithId = service.getUniqueFileId(
//   //       ApiHatFile(None, "testFile.png", "test", None, None, None, None, None, None, None, None, None)
//   //     )

//   //     fileWithId.map(_.fileId) must beSome.await(3, 10.seconds)
//   //     fileWithId.map(_.fileId.get) must equalTo("testtestfile.png").await(3, 10.seconds)
//   //   }

//   // it should  "deduplicate file IDs by adding numbers to the end of the filename" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]

//   //     val file = ApiHatFile(None,
//   //                           "testFile.png",
//   //                           "test",
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           Some(HatFileStatus.New()),
//   //                           None,
//   //                           None
//   //     )

//   //     val fileWithId = for {
//   //       first <- service.getUniqueFileId(file)
//   //       _ <- service.save(first)
//   //       second <- service.getUniqueFileId(file)
//   //       _ <- service.save(second)
//   //       third <- service.getUniqueFileId(file)
//   //     } yield third

//   //     fileWithId.map(_.fileId) must beSome.await(3, 10.seconds)
//   //     fileWithId.map(_.fileId.get) must equalTo("testtestfile-2.png").await(3, 10.seconds)
//   //   }
//   // }

// // -----------------------------------

//   // "The `save` method" should {
//   //   "insert new files into the database" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     val file = ApiHatFile(Some("testtestfile.png"),
//   //                           "testFile.png",
//   //                           "test",
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           Some(HatFileStatus.New()),
//   //                           None,
//   //                           None
//   //     )

//   //     val saved = service.save(file)

//   //     saved map { savedFile =>
//   //       savedFile.dateCreated must beSome
//   //       savedFile.lastUpdated must beSome
//   //       savedFile.fileId must beSome
//   //     } await (3, 10.seconds)
//   //   }

//   //   "upsert file information for existing files" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     val file = ApiHatFile(Some("testtestfile.png"),
//   //                           "testFile.png",
//   //                           "test",
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           Some(HatFileStatus.New()),
//   //                           None,
//   //                           None
//   //     )

//   //     val saved = service.save(file)

//   //     saved flatMap { savedFile =>
//   //       savedFile.dateCreated must beSome
//   //       savedFile.lastUpdated must beSome
//   //       savedFile.fileId must beSome
//   //       savedFile.fileId.get must equalTo("testtestfile.png")
//   //       val updatedFile = savedFile.copy(tags = Some(Seq("testtag")))
//   //       service.save(updatedFile)
//   //     } map { savedFile =>
//   //       savedFile.dateCreated must beSome
//   //       savedFile.fileId must beSome
//   //       savedFile.fileId.get must equalTo("testtestfile.png")
//   //       savedFile.tags must beSome
//   //       savedFile.tags.get must contain("testtag")
//   //     } await (3, 10.seconds)
//   //   }
//   // }

//   // "The `delete` method" should {
//   //   "Change file status to `Deleted`" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     val file = ApiHatFile(Some("testtestfile.png"),
//   //                           "testFile.png",
//   //                           "test",
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           Some(HatFileStatus.New()),
//   //                           None,
//   //                           None
//   //     )
//   //     val deleted = for {
//   //       _ <- service.save(file)
//   //       deleted <- service.delete("testtestfile.png")
//   //     } yield deleted

//   //     deleted.map(_.status) must equalTo(Some(HatFileStatus.Deleted())).await(3, 10.seconds)
//   //   }

//   //   "Throw error when deleting file that does not exist" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]

//   //     databaseReady.flatMap { _ =>
//   //       service.delete("testtestfile.png")
//   //     } must throwA[Exception].await(3, 10.seconds)
//   //   }
//   // }

//   // "The `getById` method" should {
//   //   "Return file information for an existing file" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     val file = ApiHatFile(Some("testtestfile.png"),
//   //                           "testFile.png",
//   //                           "test",
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           None,
//   //                           Some(HatFileStatus.New()),
//   //                           None,
//   //                           None
//   //     )

//   //     val saved = service.save(file)

//   //     saved flatMap { savedFile =>
//   //       service.getById("testtestfile.png")
//   //     } map { foundFile =>
//   //       foundFile must beSome
//   //       foundFile.get.fileId must beSome("testtestfile.png")
//   //     } await (3, 10.seconds)
//   //   }

//   //   "Return `None` for file that does not exist" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     service.getById("testtestfile.png") must beNone.await(3, 10.seconds)
//   //   }
//   // }

//   // "The `search` method" should {
//   //   "Return empty list when no files exist" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     val found   = service.search(ApiHatFile(None, "", "", None, None, None, None, None, None, None, None, None))

//   //     found must haveSize[Seq[ApiHatFile]](0).await(3, 10.seconds)
//   //   }

//   //   "Look up a single file by Id" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     val found = for {
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile.png"),
//   //                         "testFile.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       found <- service.search(
//   //                  ApiHatFile(Some("testtestfile.png"), "", "", None, None, None, None, None, None, None, None, None)
//   //                )
//   //     } yield found

//   //     found must haveSize[Seq[ApiHatFile]](1).await(3, 10.seconds)
//   //   }

//   //   "Look up files by exact source" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     val found = for {
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile.png"),
//   //                         "testFile.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-1.png"),
//   //                         "testFile.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-2.png"),
//   //                         "testFile.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       found <- service.search(ApiHatFile(None, "", "test", None, None, None, None, None, None, None, None, None))
//   //     } yield found

//   //     found must haveSize[Seq[ApiHatFile]](3).await(3, 10.seconds)
//   //   }

//   //   "Look up files by exact name" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     val found = for {
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile.png"),
//   //                         "testFile.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-1.png"),
//   //                         "testFile.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-2.png"),
//   //                         "testFile.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       found <-
//   //         service.search(ApiHatFile(None, "testFile.png", "", None, None, None, None, None, None, None, None, None))
//   //     } yield found

//   //     found must haveSize[Seq[ApiHatFile]](3).await(3, 10.seconds)

//   //     val found2 = for {
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-3.png"),
//   //                         "testFile3.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-4.png"),
//   //                         "testFile4.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-5.png"),
//   //                         "testFile5.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       found <-
//   //         service.search(ApiHatFile(None, "testFile3.png", "", None, None, None, None, None, None, None, None, None))
//   //     } yield found

//   //     found2 must haveSize[Seq[ApiHatFile]](1).await(3, 10.seconds)
//   //   }

//   //   "Look up files by tags" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     val found = for {
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile.png"),
//   //                         "testFile.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         Some(Seq("tag1")),
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-1.png"),
//   //                         "testFile1.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         Some(Seq("tag1", "tag2")),
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-2.png"),
//   //                         "testFile2.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         Some(Seq("tag1", "tag2", "tag3")),
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       foundT1 <-
//   //         service.search(ApiHatFile(None, "", "", None, None, Some(Seq("tag1")), None, None, None, None, None, None))
//   //       foundT12 <-
//   //         service.search(
//   //           ApiHatFile(None, "", "", None, None, Some(Seq("tag1", "tag2")), None, None, None, None, None, None)
//   //         )
//   //       foundT2 <-
//   //         service.search(ApiHatFile(None, "", "", None, None, Some(Seq("tag2")), None, None, None, None, None, None))
//   //       foundT123 <-
//   //         service.search(
//   //           ApiHatFile(None, "", "", None, None, Some(Seq("tag1", "tag2", "tag3")), None, None, None, None, None, None)
//   //         )
//   //       foundT3 <-
//   //         service.search(ApiHatFile(None, "", "", None, None, Some(Seq("tag3")), None, None, None, None, None, None))
//   //     } yield {
//   //       foundT1 must haveSize[Seq[ApiHatFile]](3)
//   //       foundT12 must haveSize[Seq[ApiHatFile]](2)
//   //       foundT2 must haveSize[Seq[ApiHatFile]](2)
//   //       foundT123 must haveSize[Seq[ApiHatFile]](1)
//   //       foundT3 must haveSize[Seq[ApiHatFile]](1)
//   //     }

//   //     found.await(3, 10.seconds)
//   //   }

//   //   "Look up files by status" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     val found = for {
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile.png"),
//   //                         "testFile.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-1.png"),
//   //                         "testFile1.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.Deleted()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-2.png"),
//   //                         "testFile2.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.Completed(123456L)),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       foundS1 <- service.search(
//   //                    ApiHatFile(None, "", "", None, None, None, None, None, None, Some(HatFileStatus.New()), None, None)
//   //                  )
//   //       foundS2 <-
//   //         service.search(
//   //           ApiHatFile(None, "", "", None, None, None, None, None, None, Some(HatFileStatus.Deleted()), None, None)
//   //         )
//   //       foundS3 <-
//   //         service.search(
//   //           ApiHatFile(None, "", "", None, None, None, None, None, None, Some(HatFileStatus.Completed(0L)), None, None)
//   //         )
//   //     } yield {
//   //       foundS1 must haveSize[Seq[ApiHatFile]](1)
//   //       foundS2 must haveSize[Seq[ApiHatFile]](1)
//   //       foundS3 must haveSize[Seq[ApiHatFile]](1)
//   //     }

//   //     found.await(3, 10.seconds)
//   //   }

//   //   "Search files by description" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]
//   //     val found = for {
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile.png"),
//   //                         "testFile.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some("A rather short description"),
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(Some("testtestfile-1.png"),
//   //                         "testFile1.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some("A long description"),
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              )
//   //            )
//   //       _ <- service.save(
//   //              ApiHatFile(
//   //                Some("testtestfile-2.png"),
//   //                "testFile2.png",
//   //                "test",
//   //                None,
//   //                None,
//   //                None,
//   //                None,
//   //                Some("A really long description than most people would use for their photos"),
//   //                None,
//   //                Some(HatFileStatus.New()),
//   //                None,
//   //                None
//   //              )
//   //            )
//   //       foundT1 <-
//   //         service.search(ApiHatFile(None, "", "", None, None, None, None, Some("long"), None, None, None, None))
//   //       foundT2 <-
//   //         service.search(ApiHatFile(None, "", "", None, None, None, None, Some("short"), None, None, None, None))
//   //       foundT3 <- service.search(
//   //                    ApiHatFile(None, "", "", None, None, None, None, Some("a description"), None, None, None, None)
//   //                  )
//   //     } yield {
//   //       foundT1 must haveSize[Seq[ApiHatFile]](2)
//   //       foundT2 must haveSize[Seq[ApiHatFile]](1)
//   //       foundT3 must haveSize[Seq[ApiHatFile]](3)
//   //     }

//   //     found.await(3, 10.seconds)
//   //   }
//   // }

//   // "The `grantAccess` method" should {
//   //   "Grant file detail access to an existing user" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]

//   //     val granted = for {
//   //       file <- service.save(
//   //                 ApiHatFile(Some("testtestfile.png"),
//   //                            "testFile.png",
//   //                            "test",
//   //                            None,
//   //                            None,
//   //                            None,
//   //                            None,
//   //                            None,
//   //                            None,
//   //                            Some(HatFileStatus.New()),
//   //                            None,
//   //                            None
//   //                 )
//   //               )
//   //       _ <- service.grantAccess(file, dataDebitUser, content = false)
//   //       _ <- service.grantAccess(file, dataCreditUser, content = true)
//   //       granted <- service.getById("testtestfile.png")
//   //     } yield {
//   //       granted must beSome
//   //       granted.get.contentPublic must beSome(false)
//   //       granted.get.permissions must beSome
//   //       granted.get.permissions.get must haveSize[Seq[ApiHatFilePermissions]](2)
//   //       granted.get.permissions.get must contain(ApiHatFilePermissions(dataDebitUser.userId, contentReadable = false))
//   //       granted.get.permissions.get must contain(ApiHatFilePermissions(dataCreditUser.userId, contentReadable = true))
//   //     }

//   //     granted.await(3, 10.seconds)
//   //   }
//   // }

//   // "The `restrictAccess` method" should {
//   //   "Restrict file access" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]

//   //     val granted = for {
//   //       file <- service.save(
//   //                 ApiHatFile(Some("testtestfile.png"),
//   //                            "testFile.png",
//   //                            "test",
//   //                            None,
//   //                            None,
//   //                            None,
//   //                            None,
//   //                            None,
//   //                            None,
//   //                            Some(HatFileStatus.New()),
//   //                            None,
//   //                            None
//   //                 )
//   //               )
//   //       _ <- service.grantAccess(file, dataCreditUser, content = false)
//   //       _ <- service.grantAccess(file, dataDebitUser, content = true)
//   //       _ <- service.restrictAccess(file, dataCreditUser)
//   //       granted <- service.getById("testtestfile.png")
//   //     } yield {
//   //       granted must beSome
//   //       granted.get.contentPublic must beSome(false)
//   //       granted.get.permissions must beSome
//   //       granted.get.permissions.get must haveSize[Seq[ApiHatFilePermissions]](1)
//   //       granted.get.permissions.get must contain(ApiHatFilePermissions(dataDebitUser.userId, contentReadable = true))
//   //     }

//   //     granted.await(3, 10.seconds)
//   //   }
//   // }

//   // "The `grantAccessPattern` method" should {
//   //   "Grant file access to an existing user for a matching file access pattern" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]

//   //     val granted = for {
//   //       file1 <- service.save(
//   //                  ApiHatFile(Some("testtestfile-1.png"),
//   //                             "testFile.png",
//   //                             "test",
//   //                             None,
//   //                             None,
//   //                             Some(Seq("tag1", "tag2")),
//   //                             None,
//   //                             None,
//   //                             None,
//   //                             Some(HatFileStatus.New()),
//   //                             None,
//   //                             None
//   //                  )
//   //                )
//   //       file2 <- service.save(
//   //                  ApiHatFile(Some("testtestfile-2.png"),
//   //                             "testFile.png",
//   //                             "test",
//   //                             None,
//   //                             None,
//   //                             Some(Seq("tag1", "tag2")),
//   //                             None,
//   //                             None,
//   //                             None,
//   //                             Some(HatFileStatus.New()),
//   //                             None,
//   //                             None
//   //                  )
//   //                )
//   //       file3 <- service.save(
//   //                  ApiHatFile(Some("testtestfile-3.png"),
//   //                             "testFile.png",
//   //                             "test",
//   //                             None,
//   //                             None,
//   //                             Some(Seq("tag1")),
//   //                             None,
//   //                             None,
//   //                             None,
//   //                             Some(HatFileStatus.New()),
//   //                             None,
//   //                             None
//   //                  )
//   //                )
//   //       _ <- service.grantAccessPattern(
//   //              ApiHatFile(None,
//   //                         "testFile.png",
//   //                         "test",
//   //                         None,
//   //                         None,
//   //                         Some(Seq("tag1", "tag2")),
//   //                         None,
//   //                         None,
//   //                         None,
//   //                         Some(HatFileStatus.New()),
//   //                         None,
//   //                         None
//   //              ),
//   //              dataDebitUser,
//   //              content = false
//   //            )
//   //       granted <- service.search(
//   //                    ApiHatFile(None,
//   //                               "testFile.png",
//   //                               "test",
//   //                               None,
//   //                               None,
//   //                               Some(Seq("tag1")),
//   //                               None,
//   //                               None,
//   //                               None,
//   //                               Some(HatFileStatus.New()),
//   //                               None,
//   //                               None
//   //                    )
//   //                  )
//   //     } yield {
//   //       granted must haveSize[Seq[ApiHatFile]](3)

//   //       val gfile1 = granted.find(_.fileId.contains("testtestfile-1.png"))
//   //       gfile1 must beSome
//   //       gfile1.get.permissions.get must haveSize[Seq[ApiHatFilePermissions]](1)
//   //       gfile1.get.permissions.get must contain(ApiHatFilePermissions(dataDebitUser.userId, contentReadable = false))

//   //       val gfile2 = granted.find(_.fileId.contains("testtestfile-2.png"))
//   //       gfile2 must beSome
//   //       gfile2.get.permissions.get must haveSize[Seq[ApiHatFilePermissions]](1)
//   //       gfile2.get.permissions.get must contain(ApiHatFilePermissions(dataDebitUser.userId, contentReadable = false))

//   //       val gfile3 = granted.find(_.fileId.contains("testtestfile-3.png"))
//   //       gfile3 must beSome
//   //       gfile3.get.permissions.get must beEmpty
//   //     }

//   //     granted.await(3, 10.seconds)
//   //   }
//   // }

//   // "The `restrictAccessPattern` method" should {
//   //   "Restrict file access to an existing user for a matching file access pattern" in {
//   //     val service = application.injector.instanceOf[FileMetadataService]

//   //     val granted = for {
//   //       file1 <- service.save(
//   //                  ApiHatFile(Some("testtestfile-1.png"),
//   //                             "testFile.png",
//   //                             "test",
//   //                             None,
//   //                             None,
//   //                             Some(Seq("tag1", "tag2")),
//   //                             None,
//   //                             None,
//   //                             None,
//   //                             Some(HatFileStatus.New()),
//   //                             None,
//   //                             None
//   //                  )
//   //                )
//   //       file2 <- service.save(
//   //                  ApiHatFile(Some("testtestfile-2.png"),
//   //                             "testFile.png",
//   //                             "test",
//   //                             None,
//   //                             None,
//   //                             Some(Seq("tag1", "tag2")),
//   //                             None,
//   //                             None,
//   //                             None,
//   //                             Some(HatFileStatus.New()),
//   //                             None,
//   //                             None
//   //                  )
//   //                )
//   //       file3 <- service.save(
//   //                  ApiHatFile(Some("testtestfile-3.png"),
//   //                             "testFile.png",
//   //                             "test",
//   //                             None,
//   //                             None,
//   //                             Some(Seq("tag1")),
//   //                             None,
//   //                             None,
//   //                             None,
//   //                             Some(HatFileStatus.New()),
//   //                             None,
//   //                             None
//   //                  )
//   //                )
//   //       _ <- service.grantAccessPattern(ApiHatFile(None,
//   //                                                  "testFile.png",
//   //                                                  "test",
//   //                                                  None,
//   //                                                  None,
//   //                                                  Some(Seq("tag1")),
//   //                                                  None,
//   //                                                  None,
//   //                                                  None,
//   //                                                  Some(HatFileStatus.New()),
//   //                                                  None,
//   //                                                  None
//   //                                       ),
//   //                                       dataDebitUser,
//   //                                       content = false
//   //            )
//   //       _ <- service.restrictAccessPattern(ApiHatFile(None,
//   //                                                     "testFile.png",
//   //                                                     "test",
//   //                                                     None,
//   //                                                     None,
//   //                                                     Some(Seq("tag1", "tag2")),
//   //                                                     None,
//   //                                                     None,
//   //                                                     None,
//   //                                                     Some(HatFileStatus.New()),
//   //                                                     None,
//   //                                                     None
//   //                                          ),
//   //                                          dataDebitUser
//   //            )
//   //       granted <- service.search(
//   //                    ApiHatFile(None,
//   //                               "testFile.png",
//   //                               "test",
//   //                               None,
//   //                               None,
//   //                               Some(Seq("tag1")),
//   //                               None,
//   //                               None,
//   //                               None,
//   //                               Some(HatFileStatus.New()),
//   //                               None,
//   //                               None
//   //                    )
//   //                  )
//   //     } yield {
//   //       granted must haveSize[Seq[ApiHatFile]](3)

//   //       val gfile1 = granted.find(_.fileId.contains("testtestfile-1.png"))
//   //       gfile1 must beSome
//   //       gfile1.get.permissions.get must beEmpty

//   //       val gfile2 = granted.find(_.fileId.contains("testtestfile-2.png"))
//   //       gfile2 must beSome
//   //       gfile2.get.permissions.get must beEmpty

//   //       val gfile3 = granted.find(_.fileId.contains("testtestfile-3.png"))
//   //       gfile3 must beSome
//   //       gfile3.get.permissions.get must haveSize[Seq[ApiHatFilePermissions]](1)
//   //       gfile3.get.permissions.get must contain(ApiHatFilePermissions(dataDebitUser.userId, contentReadable = false))
//   //     }

//   //     granted.await(3, 10.seconds)
//   //   }
//   // }
// }
