package io.liquidsoftware.acl.recipes.lists

import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import io.liquidsoftware.acl.aclCatalog
import kotlin.test.Test
import kotlin.test.assertEquals

// Mirrors docs/recipes/lists-and-queries.md. If you change an example there, change it here too.

private data class User(val id: String, val blockedBy: Set<String> = emptySet())

private data class Note(
    val id: String,
    val ownerId: String,
    val isPublic: Boolean = false,
    val sharedWith: Set<String> = emptySet(),
)

private val acl = aclCatalog<User> {
    policy<Note> {
        allow(Read, Write) { user, note -> user.id == note.ownerId }
        allow(Read) { user, note -> user.id in note.sharedWith }
        allow(Read) { user, note -> note.isPublic && note.ownerId !in user.blockedBy }
    }
}

// Stands in for a table; readableCandidates is the WHERE clause.
private class NoteQueries(private val rows: List<Note>) {
    fun readableCandidates(user: User): Sequence<Note> =
        rows.asSequence().filter { it.ownerId == user.id || user.id in it.sharedWith || it.isPublic }
}

private data class NoteView(val note: Note, val canEdit: Boolean)

class ListsAndQueriesRecipeTest {
    private val queries = NoteQueries(
        listOf(
            Note("n1", ownerId = "alice"),
            Note("n2", ownerId = "bob", isPublic = true),
            Note("n3", ownerId = "mallory", isPublic = true),
            Note("n4", ownerId = "bob", sharedWith = setOf("alice")),
            Note("n5", ownerId = "carol"),
            Note("n6", ownerId = "carol", isPublic = true),
        ),
    )
    private val alice = User("alice", blockedBy = setOf("mallory"))

    private fun visibleNotes(user: User): List<Note> =
        queries.readableCandidates(user).filter(acl.forSubject(user)::canRead).toList()

    private fun visiblePage(user: User, size: Int): List<Note> =
        queries.readableCandidates(user).filter(acl.forSubject(user)::canRead).take(size).toList()

    private fun noteList(user: User): List<NoteView> {
        val access = acl.forSubject(user)
        return visibleNotes(user).map { NoteView(it, canEdit = access.canWrite(it)) }
    }

    @Test
    fun narrow_in_the_query_confirm_with_the_catalog() {
        assertEquals(listOf("n1", "n2", "n4", "n6"), visibleNotes(alice).map { it.id })
    }

    @Test
    fun pages_stay_full() {
        assertEquals(listOf("n1", "n2", "n4"), visiblePage(alice, size = 3).map { it.id })
    }

    @Test
    fun decisions_for_the_screen() {
        assertEquals(listOf(true, false, false, false), noteList(alice).map { it.canEdit })
    }
}
