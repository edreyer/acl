package io.liquidsoftware.common.security.acl.arrow

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
import io.liquidsoftware.common.security.acl.SecuredResource
import io.liquidsoftware.common.security.acl.authorizer
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
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
  fun `ensureCanRead allows reader access`() {
    val acl = Acl.of("appointment-1", "user-1", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())

    val result = either {
      aclChecker.ensureCanRead(subject, acl)
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `ensureCanWrite raises AccessDenied with acl context for denied access`() {
    val acl = Acl.of("appointment-1", "user-1", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())

    val result = either {
      aclChecker.ensureCanWrite(subject, acl)
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    val context = assertInstanceOf(DenialContext.Acl::class.java, error.context)
    assertEquals("appointment-1", context.resourceId)
    assertEquals(Permission.WRITE, error.permission)
    assertEquals("user-1", context.subjectId)
  }

  @Test
  fun `ensureCanWrite allows writer access`() {
    val acl = Acl.of("appointment-1", "user-1", AclRole.WRITER)
    val subject = AccessSubject("user-1", emptySet())

    val result = either {
      aclChecker.ensureCanWrite(subject, acl)
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `ensureCanManage allows manager access`() {
    val acl = Acl.of("appointment-1", "user-1", AclRole.MANAGER)
    val subject = AccessSubject("user-1", emptySet())

    val result = either {
      aclChecker.ensureCanManage(subject, acl)
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `subject extension ensureCanRead allows reader access`() {
    val acl = Acl.of("appointment-1", "user-1", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())

    val result = with(aclChecker) {
      either {
        subject.ensureCanRead(acl)
      }
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `subject extension ensureCanWrite raises AccessDenied with acl context for denied access`() {
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
  fun `subject extension ensureCanWrite allows writer access`() {
    val acl = Acl.of("appointment-1", "user-1", AclRole.WRITER)
    val subject = AccessSubject("user-1", emptySet())

    val result = with(aclChecker) {
      either {
        subject.ensureCanWrite(acl)
      }
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `subject extension ensureCanManage allows manager access`() {
    val acl = Acl.of("appointment-1", "user-1", AclRole.MANAGER)
    val subject = AccessSubject("user-1", emptySet())

    val result = with(aclChecker) {
      either {
        subject.ensureCanManage(acl)
      }
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `subject extension ensureCanRead supports secured resources`() {
    val subject = AccessSubject("user-1", emptySet())
    val resource = TestResource(Acl.of("appointment-1", "user-1", AclRole.READER))

    val result = with(aclChecker) {
      either {
        subject.ensureCanRead(resource)
      }
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `subject extension ensureCanWrite raises AccessDenied with acl context for secured resources`() {
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
  fun `ensurePermission raises requested permission in error`() {
    val acl = Acl.of("appointment-1", "user-1", AclRole.READER)
    val subject = AccessSubject("user-1", emptySet())

    val result = either {
      aclChecker.ensurePermission(subject, acl, Permission.MANAGE)
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    val context = assertInstanceOf(DenialContext.Acl::class.java, error.context)
    assertEquals("appointment-1", context.resourceId)
    assertEquals(Permission.MANAGE, error.permission)
    assertEquals("user-1", context.subjectId)
  }

  @Test
  fun `subject extension ensureCanManage supports secured resources`() {
    val subject = AccessSubject("user-1", emptySet())
    val resource = TestResource(Acl.of("appointment-1", "user-1", AclRole.MANAGER))

    val result = with(aclChecker) {
      either {
        subject.ensureCanManage(resource)
      }
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `subject extension ensureCanRead supports anonymous fallback on secured resources`() {
    val subject = AccessSubject("user-1", emptySet())
    val resource = TestResource(
      Acl(
        resourceId = "appointment-1",
        userRoleMap = mapOf(ANONYMOUS_SUBJECT_ID to AclRole.READER),
      ),
    )

    val result = with(aclChecker) {
      either {
        subject.ensureCanRead(resource)
      }
    }

    assertInstanceOf(Either.Right::class.java, result)
  }

  @Test
  fun `authorizer ensureCanRead allows access`() = runBlocking {
    val user = User(id = "reader-1", roles = setOf(Role.DOCUMENT_READER))
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = either {
      documentAccess.ensureCanRead(user, document)
    }

    assertInstanceOf(Either.Right::class.java, result)
    Unit
  }

  @Test
  fun `authorizer ensureHasAccess allows access`() = runBlocking {
    val user = User(id = "editor-1", roles = setOf(Role.DOCUMENT_EDITOR))
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = either {
      documentAccess.ensureHasAccess(user, document, Permission.WRITE)
    }

    assertInstanceOf(Either.Right::class.java, result)
    Unit
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
  fun `authorizer ensureCanWrite allows access`() = runBlocking {
    val user = User(id = "editor-1", roles = setOf(Role.DOCUMENT_EDITOR))
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = either {
      documentAccess.ensureCanWrite(user, document)
    }

    assertInstanceOf(Either.Right::class.java, result)
    Unit
  }

  @Test
  fun `authorizer ensureCanManage allows access`() = runBlocking {
    val user = User(id = "owner-1")
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = either {
      documentAccess.ensureCanManage(user, document)
    }

    assertInstanceOf(Either.Right::class.java, result)
    Unit
  }

  @Test
  fun `authorizer ensureCanRead can attach structured denial metadata`() = runBlocking {
    val user = User(id = "user-1")
    val document = Document(id = "doc-1", ownerId = "owner-1")

    val result = either {
      documentAccess.ensureCanRead(
        user,
        document,
      ) { subject, resource, permission ->
        DenialContext.Metadata(
          values = mapOf(
            "subjectId" to subject.id,
            "documentId" to resource.id,
            "permission" to permission.name,
          ),
        )
      }
    }

    val error = assertInstanceOf(AccessDenied::class.java, (result as Either.Left).value)
    val context = assertInstanceOf(DenialContext.Metadata::class.java, error.context)
    assertEquals("user-1", context.values["subjectId"])
    assertEquals("doc-1", context.values["documentId"])
    assertEquals("READ", context.values["permission"])
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

    assertInstanceOf(Either.Right::class.java, result)
    Unit
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

    assertInstanceOf(Either.Right::class.java, result)
    Unit
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

    assertInstanceOf(Either.Right::class.java, result)
    Unit
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
    assertInstanceOf(DenialContext.Unknown::class.java, authorizerError.context)
    Unit
  }
}
