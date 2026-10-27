package io.liquidsoftware.acl.recipes.results

import io.liquidsoftware.acl.AccessDecision
import io.liquidsoftware.acl.DenialReason
import io.liquidsoftware.acl.NoMatchingAllowRule
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import io.liquidsoftware.acl.aclCatalog
import kotlin.test.Test
import kotlin.test.assertEquals

// Mirrors docs/recipes/denials-as-results.md. If you change an example there, change it here too.

private data class User(val id: String)
private data class Note(val ownerId: String, val text: String, val sharedWith: Set<String> = emptySet())

private val acl = aclCatalog<User> {
    policy<Note> {
        allow(Read, Write) { user, note -> user.id == note.ownerId }
        allow(Read) { user, note -> user.id in note.sharedWith }
    }
}

private sealed interface EditResult {
    data class Edited(val note: Note) : EditResult
    data object NotFound : EditResult
    data class Forbidden(val reason: DenialReason) : EditResult
}

private class NoteService(private val notes: MutableMap<String, Note>) {
    fun edit(user: User, noteId: String, text: String): EditResult {
        val note = notes[noteId] ?: return EditResult.NotFound
        return when (val decision = acl.decide(user, Write, note)) {
            AccessDecision.Granted -> EditResult.Edited(note.copy(text = text).also { notes[noteId] = it })
            // Don't confirm that a note exists to someone who may not even read it.
            is AccessDecision.Denied -> if (acl.canRead(user, note)) EditResult.Forbidden(decision.reason) else EditResult.NotFound
        }
    }
}

private fun EditResult.status(): Int = when (this) {
    is EditResult.Edited -> 200
    EditResult.NotFound -> 404
    is EditResult.Forbidden -> 403
}

class DenialsAsResultsRecipeTest {
    private val alice = User("alice")
    private val bob = User("bob")
    private val carol = User("carol")

    @Test
    fun denials_become_results() {
        val service = NoteService(mutableMapOf("plan" to Note("alice", "Plan", sharedWith = setOf("bob"))))

        assertEquals(EditResult.Edited(Note("alice", "Plan v2", sharedWith = setOf("bob"))), service.edit(alice, "plan", "Plan v2"))
        assertEquals(EditResult.Forbidden(NoMatchingAllowRule(Write, Note::class)), service.edit(bob, "plan", "hi"))
        assertEquals(EditResult.NotFound, service.edit(carol, "plan", "hi"))
        assertEquals(EditResult.NotFound, service.edit(alice, "missing", "hi"))

        assertEquals(403, service.edit(bob, "plan", "hi").status())
        assertEquals(404, service.edit(carol, "plan", "hi").status())
    }
}
