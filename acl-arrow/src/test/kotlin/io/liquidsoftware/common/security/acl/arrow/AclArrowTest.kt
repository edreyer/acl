package io.liquidsoftware.common.security.acl.arrow

import arrow.core.Either
import arrow.core.raise.either
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.AccessDenied
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.AclRole
import io.liquidsoftware.common.security.acl.Authorizer
import io.liquidsoftware.common.security.acl.AuthorizationError
import io.liquidsoftware.common.security.acl.DenialContext
import io.liquidsoftware.common.security.acl.Permission
import io.liquidsoftware.common.security.acl.SecuredResource
import io.liquidsoftware.common.security.acl.authorizer
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AclArrowTest {

  private val aclChecker = AclChecker()
  private val documentAccess = testDocumentAccess()

  private data class TestResource(
    private val resourceAcl: Acl,
  ) : SecuredResource {
    override fun acl(): Acl = resourceAcl
  }

  private enum class Role {
    ADMIN,
    DOCUMENT_READER,
    DOCUMENT_EDITOR,
  }

  private data class User(
    val id: String,
    val roles: Set<Role> = emptySet(),
  )

  private data class Document(
    val id: String,
    val ownerId: String,
  )

  private fun testDocumentAccess(): Authorizer<User, Document> =
    authorizer {
      canManage { user, document ->
        user.id == document.ownerId || Role.ADMIN in user.roles
      }

      canWrite { user, document ->
        canManage(user, document) || Role.DOCUMENT_EDITOR in user.roles
      }

      canRead { user, document ->
        canWrite(user, document) || Role.DOCUMENT_READER in user.roles
      }
    }

  @Test
  fun `ensureCanRead allows reader access`() = runBlocking {
    val acl = Acl.of("appointment-1", "user-1", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())

    val result = either<AuthorizationError, Unit> {
      aclChecker.ensureCanRead(subject, acl)
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `ensureCanWrite raises AccessDenied with acl context for denied access`() = runBlocking {
    val acl = Acl.of("appointment-1", "user-1", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())

    val result = either<AuthorizationError, Unit> {
      aclChecker.ensureCanWrite(subject, acl)
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    val context = assertInstanceOf(DenialContext.Acl::class.java, error.context)
    assertEquals("appointment-1", context.resourceId)
    assertEquals(Permission.WRITE, error.permission)
    assertEquals("user-1", context.subjectId)
  }

  @Test
  fun `ensureCanManage allows manager access`() = runBlocking {
    val acl = Acl.of("appointment-1", "user-1", AclRole.MANAGER)
    val subject = AccessSubject("user-1", emptySet())

    val result = either {
      aclChecker.ensureCanManage(subject, acl)
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `subject extension ensureCanRead allows reader access`() = runBlocking {
    val acl = Acl.of("appointment-1", "user-1", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())

    val result = with(aclChecker) {
      either<AuthorizationError, Unit> {
        subject.ensureCanRead(acl)
      }
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `subject extension ensureCanWrite raises AccessDenied with acl context for denied access`() = runBlocking {
    val acl = Acl.of("appointment-1", "user-1", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())

    val result = with(aclChecker) {
      either {
        subject.ensureCanWrite(acl)
      }
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    val context = assertInstanceOf(DenialContext.Acl::class.java, error.context)
    assertEquals("appointment-1", context.resourceId)
    assertEquals(Permission.WRITE, error.permission)
    assertEquals("user-1", context.subjectId)
  }

  @Test
  fun `subject extension ensureCanManage allows manager access`() = runBlocking {
    val acl = Acl.of("appointment-1", "user-1", AclRole.MANAGER)
    val subject = AccessSubject("user-1", emptySet())

    val result = with(aclChecker) {
      either {
        subject.ensureCanManage(acl)
      }
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `subject extension ensureCanRead supports secured resources`() = runBlocking {
    val subject = AccessSubject("user-1", emptySet())
    val resource = TestResource(Acl.of("appointment-1", "user-1", AclRole.READER))

    val result = with(aclChecker) {
      either {
        subject.ensureCanRead(resource)
      }
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `subject extension ensureCanWrite raises AccessDenied with acl context for secured resources`() = runBlocking {
    val subject = AccessSubject("user-1", emptySet())
    val resource = TestResource(Acl.of("appointment-1", "user-1", AclRole.READER))

    val result = with(aclChecker) {
      either {
        subject.ensureCanWrite(resource)
      }
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    val context = assertInstanceOf(DenialContext.Acl::class.java, error.context)
    assertEquals("appointment-1", context.resourceId)
    assertEquals(Permission.WRITE, error.permission)
    assertEquals("user-1", context.subjectId)
  }

  @Test
  fun `ensurePermission raises requested permission in error`() = runBlocking {
    val acl = Acl.of("appointment-1", "user-1", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())

    val result = either<AuthorizationError, Unit> {
      aclChecker.ensurePermission(subject, acl, Permission.MANAGE)
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    val context = assertInstanceOf(DenialContext.Acl::class.java, error.context)
    assertEquals("appointment-1", context.resourceId)
    assertEquals(Permission.MANAGE, error.permission)
    assertEquals("user-1", context.subjectId)
  }

  @Test
  fun `subject extension ensureCanManage supports secured resources`() = runBlocking {
    val subject = AccessSubject("user-1", emptySet())
    val resource = TestResource(Acl.of("appointment-1", "user-1", AclRole.MANAGER))

    val result = with(aclChecker) {
      either {
        subject.ensureCanManage(resource)
      }
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `subject extension ensureCanRead supports anonymous fallback on secured resources`() = runBlocking {
    val subject = AccessSubject("user-1", emptySet())
    val resource = TestResource(
      Acl(
        resourceId = "appointment-1",
        userRoleMap = mapOf("u_anonymous" to AclRole.READER),
      ),
    )

    val result = with(aclChecker) {
      either {
        subject.ensureCanRead(resource)
      }
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `authorizer ensureCanRead allows access`() = runBlocking {
    val user = User(id = "reader-1", roles = setOf(Role.DOCUMENT_READER))
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = either<AuthorizationError, Unit> {
      documentAccess.ensureCanRead(user, document)
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `authorizer ensureHasAccess allows access`() = runBlocking {
    val user = User(id = "editor-1", roles = setOf(Role.DOCUMENT_EDITOR))
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = either<AuthorizationError, Unit> {
      documentAccess.ensureHasAccess(user, document, Permission.WRITE)
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `authorizer ensureHasAccess raises AccessDenied for denied access`() = runBlocking {
    val user = User(id = "reader-1", roles = setOf(Role.DOCUMENT_READER))
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = either<AuthorizationError, Unit> {
      documentAccess.ensureHasAccess(user, document, Permission.WRITE)
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    assertEquals(Permission.WRITE, error.permission)
  }

  @Test
  fun `authorizer ensureCanWrite raises AccessDenied for denied access`() = runBlocking {
    val user = User(id = "reader-1", roles = setOf(Role.DOCUMENT_READER))
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = either<AuthorizationError, Unit> {
      documentAccess.ensureCanWrite(user, document)
    }

    val error = (result as Either.Left).value
    assertInstanceOf(AccessDenied::class.java, error)
    assertEquals(Permission.WRITE, error.permission)
  }

  @Test
  fun `authorizer ensureCanManage raises AccessDenied for denied access`() = runBlocking {
    val user = User(id = "editor-1", roles = setOf(Role.DOCUMENT_EDITOR))
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = either<AuthorizationError, Unit> {
      documentAccess.ensureCanManage(user, document)
    }

    val error = (result as Either.Left).value
    assertInstanceOf(AccessDenied::class.java, error)
    assertEquals(Permission.MANAGE, error.permission)
  }

  @Test
  fun `subject extension ensureCanManage supports authorizers`() = runBlocking {
    val user = User(id = "owner-1")
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = with(documentAccess) {
      either<AuthorizationError, Unit> {
        user.ensureCanManage(document)
      }
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `subject extension ensureCanWrite supports authorizers`() = runBlocking {
    val user = User(id = "editor-1", roles = setOf(Role.DOCUMENT_EDITOR))
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = with(documentAccess) {
      either<AuthorizationError, Unit> {
        user.ensureCanWrite(document)
      }
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `subject extension ensureHasAccess supports authorizers`() = runBlocking {
    val user = User(id = "editor-1", roles = setOf(Role.DOCUMENT_EDITOR))
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = with(documentAccess) {
      either<AuthorizationError, Unit> {
        user.ensureHasAccess(document, Permission.WRITE)
      }
    }

    assertTrue(result is Either.Right)
  }

  @Test
  fun `subject extension ensureCanRead raises AccessDenied for denied authorizer access`() = runBlocking {
    val user = User(id = "user-1")
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = with(documentAccess) {
      either<AuthorizationError, Unit> {
        user.ensureCanRead(document)
      }
    }

    val error = (result as Either.Left).value
    assertInstanceOf(AccessDenied::class.java, error)
    assertEquals(Permission.READ, error.permission)
  }

  @Test
  fun `authorization errors remain subtype-specific`() = runBlocking {
    val acl = Acl.of("appointment-1", "user-1", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())
    val document = Document(id = "doc-1", ownerId = "owner-1")
    val user = User(id = "user-1")

    val lowLevelResult = either<AuthorizationError, Unit> {
      aclChecker.ensureCanWrite(subject, acl)
    }
    val authorizerResult = either<AuthorizationError, Unit> {
      documentAccess.ensureCanWrite(user, document)
    }

    val lowLevelError = assertInstanceOf(AccessDenied::class.java, (lowLevelResult as Either.Left).value)
    val authorizerError = assertInstanceOf(AccessDenied::class.java, (authorizerResult as Either.Left).value)
    assertInstanceOf(DenialContext.Acl::class.java, lowLevelError.context)
    assertTrue(authorizerError.context is DenialContext.Unknown)
  }
}
