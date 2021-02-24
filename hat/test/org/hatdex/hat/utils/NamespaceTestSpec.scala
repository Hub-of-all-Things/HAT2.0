package org.hatdex.hat.utils

import org.hatdex.hat.NamespaceUtils._
import io.dataswift.models.hat.{ NamespaceRead, NamespaceWrite, UserRole }
import org.specs2.mock.Mockito
import play.api.Logger
import play.api.test.{ PlaySpecification }

class NamespaceTestSpec extends PlaySpecification with Mockito {

  val logger = Logger(this.getClass)
  sequential

  "The Namespace Verification" should {
    "NamespaceUtils: Allow the correct namespace" in {
      val namespace              = "correctnamespace"
      val applicationPermissions = List(NamespaceWrite("correctnamespace"), NamespaceRead("correctnamespace"))

      val readRoles  = NamespaceUtils.testReadNamespacePermissions(applicationPermissions, namespace)
      val writeRoles = NamespaceUtils.testWriteNamespacePermissions(applicationPermissions, namespace)

      readRoles == writeRoles
    }

    "NamespaceUtils: Disallow the incorrect namespace" in {
      val namespace              = "incorrectnamespace"
      val applicationPermissions = List(NamespaceWrite("correctnamespace"), NamespaceRead("correctnamespace"))

      val readRoles  = NamespaceUtils.testReadNamespacePermissions(applicationPermissions, namespace)
      val writeRoles = NamespaceUtils.testWriteNamespacePermissions(applicationPermissions, namespace)

      readRoles == false
      writeRoles == false
    }

    "NamespaceUtils: Empty App Permission" in {
      val namespace              = "incorrectnamespace"
      val applicationPermissions = List.empty

      val readRoles  = NamespaceUtils.testReadNamespacePermissions(applicationPermissions, namespace)
      val writeRoles = NamespaceUtils.testWriteNamespacePermissions(applicationPermissions, namespace)

      readRoles == false
      writeRoles == false
    }

    "NamespaceUtils: Empty Namespace" in {
      val namespace              = ""
      val applicationPermissions = List(NamespaceWrite("correctnamespace"), NamespaceRead("correctnamespace"))

      val readRoles  = NamespaceUtils.testReadNamespacePermissions(applicationPermissions, namespace)
      val writeRoles = NamespaceUtils.testWriteNamespacePermissions(applicationPermissions, namespace)

      readRoles == writeRoles
    }

    "NamespaceUtils: Mis-matched types" in {
      val namespace                             = "correctnamespace"
      val applicationPermissions: Seq[UserRole] = List(NamespaceWrite("correctnamespace"))

      val readRoles  = NamespaceUtils.testReadNamespacePermissions(applicationPermissions, namespace)
      val writeRoles = NamespaceUtils.testWriteNamespacePermissions(applicationPermissions, namespace)

      readRoles == false
      writeRoles == true
    }
  }
}
