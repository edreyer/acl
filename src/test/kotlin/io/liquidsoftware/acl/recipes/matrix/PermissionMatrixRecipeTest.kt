package io.liquidsoftware.acl.recipes.matrix

import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.Operation.Manage
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import io.liquidsoftware.acl.aclCatalog
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// Mirrors docs/recipes/permission-matrix-tests.md. If you change an example there, change it here too.

private data class User(val id: String, val isAdmin: Boolean = false)
private data class Document(val ownerId: String, val isPublic: Boolean = false)
private data object Publish : Operation

private val acl = aclCatalog<User> {
    policy<Document> {
        allow(Manage) { user -> user.isAdmin }
        allow(Read, Write) { user, doc -> user.id == doc.ownerId }
        allow(Publish) { user, doc -> user.id == doc.ownerId && !doc.isPublic }
        allow(Read) { _, doc -> doc.isPublic }
    }
}

private val owner = User("ann")
private val stranger = User("sam")
private val admin = User("root", isAdmin = true)

private val draft = Document(ownerId = "ann")
private val published = Document(ownerId = "ann", isPublic = true)

private val operations = listOf(Read, Write, Manage, Publish)

private fun expect(subject: User, resource: Any, vararg allowed: Operation) =
    operations.map { operation -> Triple(subject, operation, resource) to (operation in allowed) }

private val matrix = listOf(
    expect(owner, draft, Read, Write, Publish),
    expect(owner, published, Read, Write),
    expect(stranger, draft),
    expect(stranger, published, Read),
    expect(admin, draft, Read, Write, Manage),
    expect(admin, published, Read, Write, Manage),
).flatten()

class PermissionMatrixRecipeTest {
    @Test
    fun permission_matrix() {
        val wrong = matrix.filter { (case, expected) ->
            val (subject, operation, resource) = case
            acl.can(subject, operation, resource) != expected
        }
        val report = wrong.joinToString("\n") { (case, expected) -> "$case should be ${if (expected) "allowed" else "denied"}" }
        assertTrue(wrong.isEmpty(), report)
    }

    @Test
    fun the_matrix_covers_every_operation() {
        assertEquals(6 * operations.size, matrix.size)
    }
}
