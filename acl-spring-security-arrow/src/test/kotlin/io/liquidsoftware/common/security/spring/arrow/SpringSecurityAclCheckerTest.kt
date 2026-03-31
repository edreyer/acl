package io.liquidsoftware.common.security.spring.arrow

import arrow.core.Either
import arrow.core.raise.either
import io.liquidsoftware.common.security.acl.ANONYMOUS_SUBJECT_ID
import io.liquidsoftware.common.security.acl.AccessDenied
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.AclRole
import io.liquidsoftware.common.security.acl.AuthorizationError
import io.liquidsoftware.common.security.acl.Authorizer
import io.liquidsoftware.common.security.acl.DenialContext
import io.liquidsoftware.common.security.acl.Permission
import io.liquidsoftware.common.security.acl.authorizer
import io.liquidsoftware.common.security.spring.SpringSecurityAccessSubjectProvider
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User

class SpringSecurityAclCheckerTest {

  private data class Document(
    val id: String,
    val ownerId: String,
  )

  private val checker = SpringSecurityAclChecker(
    SpringSecurityAccessSubjectProvider { authentication ->
      when (authentication) {
        is UsernamePasswordAuthenticationToken -> AccessSubject(
          userId = authentication.credentials as? String ?: ANONYMOUS_SUBJECT_ID,
          roles = authentication.authorities.mapNotNull { it.authority }.toSet(),
        )
        else -> AccessSubject(
          userId = ANONYMOUS_SUBJECT_ID,
          roles = emptySet(),
        )
      }
    },
    AclChecker(),
  )

  private val documentAccess: Authorizer<AccessSubject, Document> =
    authorizer {
      canManage { subject, document ->
        subject.userId == document.ownerId || AclChecker.ROLE_ADMIN in subject.roles
      }

      canWrite { subject, document ->
        canManage(subject, document) || "ROLE_EDITOR" in subject.roles
      }

      canRead { subject, document ->
        canWrite(subject, document) || "ROLE_READER" in subject.roles
      }
    }

  @AfterEach
  fun clearSecurityContext() {
    SecurityContextHolder.clearContext()
  }

  @Test
  fun `ensureCanRead uses current subject and succeeds for allowed access`() {
    authenticate("u_test-user", "ROLE_USER")
    val acl = Acl.of("a_test", "u_test-user", AclRole.READER)

    val result = either<AuthorizationError, Unit> {
      checker.ensureCanRead(acl)
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `ensureCanWrite uses current subject and raises AccessDenied with acl context for denied access`() {
    authenticate("u_test-user", "ROLE_USER")
    val acl = Acl.of("a_test", "u_test-user", AclRole.READER)

    val result = either<AuthorizationError, Unit> {
      checker.ensureCanWrite(acl)
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    val context = assertInstanceOf(DenialContext.Acl::class.java, error.context)
    assertEquals("a_test", context.resourceId)
    assertEquals(Permission.WRITE, error.permission)
    assertEquals("u_test-user", context.subjectId)
  }

  @Test
  fun `ensureCanWrite uses writer access and succeeds`() {
    authenticate("u_writer", "ROLE_EDITOR")
    val acl = Acl.of("a_test", "u_writer", AclRole.WRITER)

    val result = either<AuthorizationError, Unit> {
      checker.ensureCanWrite(acl)
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `ensureCanManage uses admin bypass and succeeds`() {
    authenticate("u_admin", AclChecker.ROLE_ADMIN)
    val acl = Acl.of("a_test", "someone-else", AclRole.READER)

    val result = either {
      checker.ensureCanManage(acl)
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `ensureCanRead raises AccessDenied with acl context for anonymous subject without access`() {
    val acl = Acl.of("a_test", "someone-else", AclRole.READER)

    val result = either {
      checker.ensureCanRead(acl)
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    val context = assertInstanceOf(DenialContext.Acl::class.java, error.context)
    assertEquals("a_test", context.resourceId)
    assertEquals(Permission.READ, error.permission)
    assertEquals(ANONYMOUS_SUBJECT_ID, context.subjectId)
  }

  @Test
  fun `ensureCanRead supports authorizers with current subject`() {
    runBlocking {
      authenticate("u_reader", "ROLE_READER")
      val document = Document(id = "doc-1", ownerId = "u_owner")

      val result = either {
        checker.ensureCanRead(document, documentAccess)
      }

      assertInstanceOf(Either.Right::class.java, result)
    }
  }

  @Test
  fun `ensureCanWrite supports authorizers with current subject`() {
    runBlocking {
      authenticate("u_editor", "ROLE_EDITOR")
      val document = Document(id = "doc-1", ownerId = "u_owner")

      val result = either {
        checker.ensureCanWrite(document, documentAccess)
      }

      assertInstanceOf(Either.Right::class.java, result)
    }
  }

  @Test
  fun `ensureCanManage supports authorizers with current subject`() {
    runBlocking {
      authenticate("u_owner", "ROLE_USER")
      val document = Document(id = "doc-1", ownerId = "u_owner")

      val result = either {
        checker.ensureCanManage(document, documentAccess)
      }

      assertInstanceOf(Either.Right::class.java, result)
    }
  }

  @Test
  fun `ensureCanRead forwards structured denial metadata for authorizers`() = runBlocking {
    authenticate("u_denied", "ROLE_USER")
    val document = Document(id = "doc-1", ownerId = "u_owner")

    val result = either<AuthorizationError, Unit> {
      checker.ensureCanRead(
        document,
        documentAccess,
      ) { subject, resource, permission ->
        DenialContext.Metadata(
          values = mapOf(
            "subjectId" to subject.userId,
            "resourceId" to resource.id,
            "permission" to permission.name,
          ),
        )
      }
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    val context = assertInstanceOf(DenialContext.Metadata::class.java, error.context)
    assertEquals("u_denied", context.values["subjectId"])
    assertEquals("doc-1", context.values["resourceId"])
    assertEquals("READ", context.values["permission"])
  }

  @Test
  fun `ensureHasAccess raises AccessDenied with unknown context for denied authorizer access`() = runBlocking {
    authenticate("u_reader", "ROLE_READER")
    val document = Document(id = "doc-1", ownerId = "u_owner")

    val result = either {
      checker.ensureHasAccess(document, Permission.WRITE, documentAccess)
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    assertEquals(Permission.WRITE, error.permission)
    assertEquals(DenialContext.Unknown, error.context)
  }

  private fun authenticate(userId: String, vararg roles: String) {
    val authorities = roles.map(::SimpleGrantedAuthority)
    val principal = User("$userId@example.com", "", authorities)
    SecurityContextHolder.getContext().authentication =
      UsernamePasswordAuthenticationToken(principal, userId, principal.authorities)
  }
}
