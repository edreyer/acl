package io.liquidsoftware.common.security.acl

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AclCheckerTest {

  private val aclChecker = AclChecker()

  @Test
  fun `manager can manage owned resource`() {
    val acl = Acl.of("appointment-1", "user-1", AclRole.MANAGER)
    val subject = AccessSubject("user-1", emptySet())

    assertTrue(aclChecker.hasPermission(subject, acl, Permission.MANAGE))
  }

  @Test
  fun `acl builder creates same acl as hand-built map`() {
    val dslAcl = acl("appointment-1") {
      manager("user-1")
      reader("assistant-1")
    }

    val handBuiltAcl = Acl(
      resourceId = "appointment-1",
      userRoleMap = mapOf(
        "user-1" to AclRole.MANAGER,
        "assistant-1" to AclRole.READER,
      ),
    )

    assertEquals(handBuiltAcl, dslAcl)
  }

  @Test
  fun `acl builder supports anonymous access`() {
    val acl = acl("appointment-1") {
      manager("user-1")
      anonymousReader()
    }

    assertEquals(AclRole.READER, acl.userRoleMap[ANONYMOUS_SUBJECT_ID])
    assertEquals(AclRole.MANAGER, acl.userRoleMap["user-1"])
  }

  @Test
  fun `acl builder supports anonymous writer and manager access`() {
    val writerAcl = acl("appointment-1") {
      anonymousWriter()
    }
    val managerAcl = acl("appointment-2") {
      anonymousManager()
    }

    assertEquals(AclRole.WRITER, writerAcl.userRoleMap[ANONYMOUS_SUBJECT_ID])
    assertEquals(AclRole.MANAGER, managerAcl.userRoleMap[ANONYMOUS_SUBJECT_ID])
  }

  @Test
  fun `reader cannot write owned resource`() {
    val acl = Acl.of("appointment-1", "user-1", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())

    assertFalse(aclChecker.hasPermission(subject, acl, Permission.WRITE))
  }

  @Test
  fun `anonymous subject can read resource with anonymous reader access`() {
    val acl = Acl(
      resourceId = "appointment-1",
      userRoleMap = mapOf(ANONYMOUS_SUBJECT_ID to AclRole.READER),
    )
    val subject = AccessSubject(ANONYMOUS_SUBJECT_ID, emptySet())

    assertTrue(aclChecker.hasPermission(subject, acl, Permission.READ))
  }

  @Test
  fun `admin bypass grants access`() {
    val acl = Acl.of("appointment-1", "someone-else", AclRole.READER)
    val subject = AccessSubject("admin-user", setOf(AclChecker.ROLE_ADMIN))

    assertTrue(aclChecker.hasPermission(subject, acl, Permission.MANAGE))
  }

  @Test
  fun `system bypass grants access`() {
    val acl = Acl.of("appointment-1", "someone-else", AclRole.READER)
    val subject = AccessSubject("system-user", setOf(AclChecker.ROLE_SYSTEM))

    assertTrue(aclChecker.hasPermission(subject, acl, Permission.MANAGE))
  }

  @Test
  fun `writer can read and write owned resource`() {
    val acl = Acl.of("appointment-1", "user-1", AclRole.WRITER)
    val subject = AccessSubject("user-1", emptySet())

    assertTrue(aclChecker.hasPermission(subject, acl, Permission.READ))
    assertTrue(aclChecker.hasPermission(subject, acl, Permission.WRITE))
  }

  @Test
  fun `authenticated subject falls back to anonymous access when direct role is missing`() {
    val acl = acl("appointment-1") {
      anonymousReader()
    }
    val subject = AccessSubject("user-1", emptySet())

    assertTrue(aclChecker.hasPermission(subject, acl, Permission.READ))
  }

  @Test
  fun `subject without direct or anonymous access is denied`() {
    val acl = Acl.of("appointment-1", "someone-else", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())

    assertFalse(aclChecker.hasPermission(subject, acl, Permission.READ))
  }

  @Test
  fun `checker supports custom anonymous subject id`() {
    val customChecker = AclChecker(anonymousSubjectId = "u_guest")
    val acl = Acl(
      resourceId = "appointment-1",
      userRoleMap = mapOf("u_guest" to AclRole.READER),
    )
    val subject = AccessSubject("user-1", emptySet())

    assertTrue(customChecker.hasPermission(subject, acl, Permission.READ))
  }

  @Test
  fun `checker supports custom global roles`() {
    val customChecker = AclChecker(globalRoles = setOf("ROLE_SUPPORT"))
    val acl = Acl.of("appointment-1", "someone-else", AclRole.READER)
    val subject = AccessSubject("support-user", setOf("ROLE_SUPPORT"))

    assertTrue(customChecker.hasPermission(subject, acl, Permission.MANAGE))
  }

  @Test
  fun `duplicate role assignment uses the last declared role`() {
    val acl = acl("appointment-1") {
      reader("user-1")
      writer("user-1")
    }

    assertEquals(AclRole.WRITER, acl.userRoleMap["user-1"])
  }
}
