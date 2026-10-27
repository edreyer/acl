package io.liquidsoftware.acl.recipes.audit

import io.liquidsoftware.acl.AccessDecision
import io.liquidsoftware.acl.AclCatalog
import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import io.liquidsoftware.acl.aclCatalog
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// Mirrors docs/recipes/audit-logging.md. If you change an example there, change it here too.

private data class User(val id: String)
private data class Note(val id: String, val ownerId: String)

private val acl = aclCatalog<User> {
    policy<Note> {
        allow(Read, Write) { user, note -> user.id == note.ownerId }
    }
}

private data class AuditEntry(val subjectId: String, val operation: Operation, val resource: String, val decision: AccessDecision)

private class AuditedAcl<S : Any>(
    private val acl: AclCatalog<S>,
    private val subjectId: (S) -> String,
    private val resourceId: (Any) -> String,
    private val record: (AuditEntry) -> Unit,
) {
    fun decide(subject: S, operation: Operation, resource: Any): AccessDecision =
        acl.decide(subject, operation, resource).also { decision ->
            record(AuditEntry(subjectId(subject), operation, resourceId(resource), decision))
        }

    fun can(subject: S, operation: Operation, resource: Any): Boolean = decide(subject, operation, resource).granted
}

class AuditLoggingRecipeTest {
    @Test
    fun checks_at_the_action_boundary_are_recorded() {
        val log = mutableListOf<AuditEntry>()
        val audited = AuditedAcl(
            acl,
            subjectId = User::id,
            resourceId = { resource -> if (resource is Note) "note:${resource.id}" else resource::class.simpleName.orEmpty() },
            record = log::add,
        )

        val note = Note("n1", ownerId = "alice")
        assertTrue(audited.can(User("alice"), Write, note))
        assertFalse(audited.can(User("bob"), Write, note))

        assertEquals(listOf("alice" to true, "bob" to false), log.map { it.subjectId to it.decision.granted })
        assertEquals("note:n1", log.last().resource)
        assertEquals("No rule allows Write on ${Note::class.qualifiedName}", (log.last().decision as AccessDecision.Denied).reason.message)
    }
}
