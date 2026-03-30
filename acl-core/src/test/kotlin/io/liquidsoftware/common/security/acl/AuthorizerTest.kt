package io.liquidsoftware.common.security.acl

import kotlinx.coroutines.runBlocking
import kotlin.test.assertFailsWith
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AuthorizerTest {

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

  private data class Folder(
    val id: String,
    val readerIds: Set<String> = emptySet(),
    val parent: Folder? = null,
  )

  private val documentAccess = authorizer<User, Document> {
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
  fun `owner can manage write and read document`() = runBlocking {
    val owner = User(id = "user-1")
    val document = Document(id = "doc-1", ownerId = "user-1")

    assertTrue(documentAccess.canManage(owner, document))
    assertTrue(documentAccess.canWrite(owner, document))
    assertTrue(documentAccess.canRead(owner, document))
  }

  @Test
  fun `admin can manage write and read document`() = runBlocking {
    val admin = User(id = "admin-1", roles = setOf(Role.ADMIN))
    val document = Document(id = "doc-1", ownerId = "user-1")

    assertTrue(documentAccess.canManage(admin, document))
    assertTrue(documentAccess.canWrite(admin, document))
    assertTrue(documentAccess.canRead(admin, document))
  }

  @Test
  fun `editor can write and read but not manage`() = runBlocking {
    val editor = User(id = "editor-1", roles = setOf(Role.DOCUMENT_EDITOR))
    val document = Document(id = "doc-1", ownerId = "user-1")

    assertFalse(documentAccess.canManage(editor, document))
    assertTrue(documentAccess.canWrite(editor, document))
    assertTrue(documentAccess.canRead(editor, document))
  }

  @Test
  fun `reader can read only`() = runBlocking {
    val reader = User(id = "reader-1", roles = setOf(Role.DOCUMENT_READER))
    val document = Document(id = "doc-1", ownerId = "user-1")

    assertFalse(documentAccess.canManage(reader, document))
    assertFalse(documentAccess.canWrite(reader, document))
    assertTrue(documentAccess.canRead(reader, document))
  }

  @Test
  fun `unknown user is denied`() = runBlocking {
    val user = User(id = "user-2")
    val document = Document(id = "doc-1", ownerId = "user-1")

    assertFalse(documentAccess.canManage(user, document))
    assertFalse(documentAccess.canWrite(user, document))
    assertFalse(documentAccess.canRead(user, document))
  }

  @Test
  fun `hasAccess delegates to the same permission rules`() = runBlocking {
    val editor = User(id = "editor-1", roles = setOf(Role.DOCUMENT_EDITOR))
    val document = Document(id = "doc-1", ownerId = "user-1")

    assertFalse(documentAccess.hasAccess(editor, document, Permission.MANAGE))
    assertTrue(documentAccess.hasAccess(editor, document, Permission.WRITE))
    assertTrue(documentAccess.hasAccess(editor, document, Permission.READ))
  }

  @Test
  fun `missing rule denies access by default`() = runBlocking {
    val readOnlyAccess = authorizer<User, Document> {
      canRead { _, _ -> true }
    }
    val user = User(id = "user-1")
    val document = Document(id = "doc-1", ownerId = "user-2")

    assertTrue(readOnlyAccess.canRead(user, document))
    assertFalse(readOnlyAccess.canWrite(user, document))
    assertFalse(readOnlyAccess.canManage(user, document))
  }

  @Test
  fun `circular rule dependencies fail fast`() {
    val invalidAccess = authorizer<User, Document> {
      canRead { user, document ->
        canWrite(user, document)
      }

      canWrite { user, document ->
        canRead(user, document)
      }
    }
    val user = User(id = "user-1")
    val document = Document(id = "doc-1", ownerId = "user-2")

    assertFailsWith<IllegalStateException> {
      runBlocking {
        invalidAccess.canRead(user, document)
      }
    }
  }

  @Test
  fun `same permission can recurse across related resources`() = runBlocking {
    val folderAccess = authorizer<User, Folder> {
      canRead { user, folder ->
        user.id in folder.readerIds || folder.parent?.let { canRead(user, it) } == true
      }
    }
    val user = User(id = "user-1")
    val root = Folder(id = "root", readerIds = setOf("user-1"))
    val child = Folder(id = "child", parent = root)

    assertTrue(folderAccess.canRead(user, child))
  }

  @Test
  fun `rules can compose through hasAccess`() = runBlocking {
    val documentAccess = authorizer<User, Document> {
      canManage { _, _ -> false }

      canWrite { user, document ->
        user.id == document.ownerId
      }

      canRead { user, document ->
        hasAccess(user, document, Permission.WRITE)
      }
    }
    val owner = User(id = "user-1")
    val document = Document(id = "doc-1", ownerId = "user-1")

    assertTrue(documentAccess.canRead(owner, document))
  }

  @Test
  fun `hasAccess inside a rule participates in cycle detection`() {
    val invalidAccess = authorizer<User, Document> {
      canRead { user, document ->
        hasAccess(user, document, Permission.READ)
      }
    }
    val user = User(id = "user-1")
    val document = Document(id = "doc-1", ownerId = "user-2")

    assertFailsWith<IllegalStateException> {
      runBlocking {
        invalidAccess.canRead(user, document)
      }
    }
  }

  @Test
  fun `duplicate rule definitions fail fast`() {
    assertFailsWith<IllegalStateException> {
      authorizer<User, Document> {
        canRead { _, _ -> true }
        canRead { _, _ -> false }
      }
    }
  }
}
