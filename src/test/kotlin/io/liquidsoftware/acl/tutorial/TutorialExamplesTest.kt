package io.liquidsoftware.acl.tutorial

import io.liquidsoftware.acl.AccessDecision
import io.liquidsoftware.acl.AclCatalog
import io.liquidsoftware.acl.AmbiguousPolicy
import io.liquidsoftware.acl.DenialReason
import io.liquidsoftware.acl.NoMatchingAllowRule
import io.liquidsoftware.acl.NoPolicyRegistered
import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.Operation.Manage
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import io.liquidsoftware.acl.aclCatalog
import io.liquidsoftware.acl.aclPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// Mirrors docs/tutorial.md. If you change an example there, change it here too.
// Steps 1 to 4 use their own, simpler types; steps 5 onward share the types below, as the tutorial does.

private data class User(
    val id: String,
    val isAdmin: Boolean = false,
    val teams: Set<String> = emptySet(),
)

private data class Note(
    val ownerId: String,
    val text: String,
    val isPublic: Boolean = false,
    val teamId: String? = null,
    val sharedWith: Set<String> = emptySet(),
)

private fun User.owns(note: Note) = id == note.ownerId
private fun User.isOnTeamOf(note: Note) = note.teamId != null && note.teamId in teams
private fun User.wasSharedOn(note: Note) = id in note.sharedWith

private data class Notebook(val ownerId: String, val title: String)

private val alice = User("alice", teams = setOf("design"))
private val bob = User("bob", teams = setOf("design"))
private val carol = User("carol")
private val admin = User("root", isAdmin = true)

private val roadmap = Note(ownerId = "alice", text = "Q3 roadmap", teamId = "design")
private val draft = Note(ownerId = "alice", text = "Draft", sharedWith = setOf("carol"))
private val announcement = Note(ownerId = "alice", text = "Office closed Friday", isPublic = true)

// The step 5 Note policy, for the later steps that say "as in step 5".
private val notePolicy = aclPolicy<User, Note> {
    allow(Manage) { user -> user.isAdmin }
    allow(Read, Write) { user, note -> user.owns(note) }
    allow(Read, Write) { user, note -> user.isOnTeamOf(note) }
    allow(Read) { user, note -> user.wasSharedOn(note) }
    allow(Read) { _, note -> note.isPublic }
}

private val step5Acl = aclCatalog<User> {
    policy<Note> {
        allow(Manage) { user -> user.isAdmin }
        allow(Read, Write) { user, note -> user.owns(note) }
        allow(Read, Write) { user, note -> user.isOnTeamOf(note) }
        allow(Read) { user, note -> user.wasSharedOn(note) }
        allow(Read) { _, note -> note.isPublic }
    }
}

private val notebookPolicy = aclPolicy<User, Notebook> {
    allow(Manage) { user -> user.isAdmin }
    allow(Read, Write) { user, notebook -> user.id == notebook.ownerId }
}

private data object Comment : Operation
private data object Publish : Operation

private data object Contribute : Operation {
    override fun covers(requested: Operation) =
        requested == Contribute || requested == Read || requested == Comment
}

private sealed interface NoteOperation : Operation {
    data object Comment : NoteOperation
    data object Publish : NoteOperation
    data object Archive : NoteOperation
}

private sealed interface Principal

private data class Member(val user: User) : Principal
private data class ServiceAccount(val name: String, val scopes: Set<String>) : Principal
private data object Anonymous : Principal

private open class Attachment(val noteOwnerId: String)
private class Image(noteOwnerId: String) : Attachment(noteOwnerId)
private class Recording(noteOwnerId: String, val containsPersonalData: Boolean) : Attachment(noteOwnerId)

private interface Exportable
private interface Billable
private class Invoice(val customerId: String) : Exportable, Billable

private class AccessDeniedException(val reason: DenialReason) : RuntimeException(reason.message)

private fun <S : Any> AclCatalog<S>.requireAccess(subject: S, operation: Operation, resource: Any) {
    val decision = decide(subject, operation, resource)
    if (decision is AccessDecision.Denied) throw AccessDeniedException(decision.reason)
}

private class NoteService(private val acl: AclCatalog<User>, private val notes: MutableMap<String, Note>) {
    fun visibleTo(user: User): List<Note> =
        notes.values.filter(acl.forSubject(user)::canRead)

    fun edit(user: User, noteId: String, text: String): Note {
        val note = notes.getValue(noteId)
        acl.requireAccess(user, Write, note)
        return note.copy(text = text).also { notes[noteId] = it }
    }
}

class TutorialExamplesTest {
    private object Step1 {
        data class User(val id: String)
        data class Note(val ownerId: String, val text: String)

        val acl = aclCatalog<User> {
            policy<Note> {
                allow(Read) { user, note -> user.id == note.ownerId }
            }
        }

        val alice = User("alice")
        val bob = User("bob")
        val groceries = Note(ownerId = "alice", text = "milk, eggs")
    }

    @Test
    fun step1_first_catalog() = with(Step1) {
        assertTrue(acl.canRead(alice, groceries))
        assertFalse(acl.canRead(bob, groceries))
        assertFalse(acl.canWrite(alice, groceries))
    }

    private object Step2 {
        data class User(val id: String)
        data class Note(val ownerId: String, val text: String, val isPublic: Boolean = false)

        val acl = aclCatalog<User> {
            policy<Note> {
                allow(Read, Write) { user, note -> user.id == note.ownerId }
                allow(Read) { _, note -> note.isPublic }
            }
        }

        val alice = User("alice")
        val bob = User("bob")
        val groceries = Note(ownerId = "alice", text = "milk, eggs")
        val announcement = Note(ownerId = "alice", text = "Office closed Friday", isPublic = true)
    }

    @Test
    fun step2_more_operations_more_rules() = with(Step2) {
        assertTrue(acl.canWrite(alice, groceries))
        assertTrue(acl.canRead(bob, announcement))
        assertFalse(acl.canWrite(bob, announcement))
        assertFalse(acl.canRead(bob, groceries))
    }

    private object Step3 {
        data class User(val id: String, val isAdmin: Boolean = false)
        data class Note(val ownerId: String, val text: String, val isPublic: Boolean = false)
        data class Notebook(val ownerId: String, val title: String)

        val acl = aclCatalog<User> {
            policy<Note> {
                allow(Manage) { user -> user.isAdmin }
                allow(Read, Write) { user, note -> user.id == note.ownerId }
                allow(Read) { _, note -> note.isPublic }
            }
        }

        val alice = User("alice")
        val bob = User("bob")
        val admin = User("root", isAdmin = true)
        val groceries = Note(ownerId = "alice", text = "milk, eggs")

        fun explain(decision: AccessDecision): String = when (decision) {
            AccessDecision.Granted -> "granted"
            is AccessDecision.Denied -> when (val reason = decision.reason) {
                is NoMatchingAllowRule -> "you may not ${reason.operation} this ${reason.resourceType.simpleName}"
                is NoPolicyRegistered -> "bug: no policy for ${reason.resourceType.simpleName}"
                is AmbiguousPolicy -> "bug: ${reason.message}"
            }
        }
    }

    @Test
    fun step3_subject_only_rules_and_manage() = with(Step3) {
        assertTrue(acl.canManage(admin, groceries))
        assertTrue(acl.canRead(admin, groceries))
        assertTrue(acl.canWrite(admin, groceries))
        assertFalse(acl.canManage(alice, groceries))

        val itForm = aclCatalog<Step3.User> { policy<Step3.Note> { allow(Manage) { it.isAdmin } } }
        assertTrue(itForm.canManage(admin, groceries))
    }

    @Test
    fun step4_asking_why() = with(Step3) {
        val decision = acl.decide(bob, Write, groceries)
        assertEquals(AccessDecision.Denied(NoMatchingAllowRule(Write, Step3.Note::class)), decision)
        assertEquals("No rule allows Write on ${Step3.Note::class.qualifiedName}", (decision as AccessDecision.Denied).reason.message)

        assertEquals("granted", explain(acl.decide(alice, Read, groceries)))
        assertEquals("you may not Write this Note", explain(acl.decide(bob, Write, groceries)))
        assertEquals("bug: no policy for Notebook", explain(acl.decide(alice, Read, Step3.Notebook("alice", "Recipes"))))
    }

    @Test
    fun step5_rules_from_your_domain() {
        val acl = step5Acl
        assertTrue(acl.canWrite(bob, roadmap))
        assertFalse(acl.canRead(carol, roadmap))
        assertTrue(acl.canRead(carol, draft))
        assertFalse(acl.canWrite(carol, draft))

        val registered = aclCatalog<User> { register(notePolicy) }
        assertEquals(acl.canWrite(bob, roadmap), registered.canWrite(bob, roadmap))
    }

    @Test
    fun step6_more_resource_types() {
        val inline = aclCatalog<User> {
            policy<Notebook> {
                allow(Manage) { user -> user.isAdmin }
                allow(Read, Write) { user, notebook -> user.id == notebook.ownerId }
            }
        }
        val acl = aclCatalog<User> {
            register(notePolicy)
            register(notebookPolicy)
        }

        for (catalog in listOf(inline, acl)) {
            assertTrue(catalog.canWrite(alice, Notebook("alice", "Recipes")))
            assertFalse(catalog.canRead(bob, Notebook("alice", "Recipes")))
        }
        assertTrue(acl.canWrite(bob, roadmap))

        assertFailsWith<IllegalStateException> {
            aclCatalog<User> {
                register(notebookPolicy)
                register(notebookPolicy)
            }
        }
    }

    @Test
    fun step7_checking_many_resources() {
        val notes = listOf(roadmap, draft, announcement)
        val access = step5Acl.forSubject(carol)

        assertEquals(listOf(draft, announcement), notes.filter(access::canRead))
        val (editable, readOnly) = notes.partition(access::canWrite)
        assertEquals(emptyList(), editable)
        assertEquals(notes, readOnly)
        assertFalse(notes.any(access::canWrite))
        assertEquals(
            notes.associateWith { AccessDecision.Denied(NoMatchingAllowRule(Write, Note::class)) },
            notes.associateWith { access.decide(Write, it) },
        )
    }

    @Test
    fun step8_custom_operations() {
        val acl = aclCatalog<User> {
            policy<Note> {
                allow(Manage) { user -> user.isAdmin }
                allow(Read, Write, Comment, Publish) { user, note -> user.owns(note) }
                allow(Read, Comment) { user, note -> user.wasSharedOn(note) }
            }
        }

        assertTrue(acl.can(carol, Comment, draft))
        assertFalse(acl.can(carol, Publish, draft))
        assertTrue(acl.can(alice, Publish, draft))
        assertFalse(acl.can(admin, Publish, draft))

        val both = aclCatalog<User> { policy<Note> { allow(Manage, Publish) { user -> user.isAdmin } } }
        assertTrue(both.can(admin, Publish, draft))
    }

    @Test
    fun step9_operations_that_imply_others() {
        val acl = aclCatalog<User> {
            policy<Note> {
                allow(Read, Write, Comment, Publish) { user, note -> user.owns(note) }
                allow(Contribute) { user, note -> user.isOnTeamOf(note) }
            }
        }

        assertTrue(acl.canRead(bob, roadmap))
        assertTrue(acl.can(bob, Comment, roadmap))
        assertFalse(acl.canWrite(bob, roadmap))
        assertTrue(acl.can(bob, Contribute, roadmap))
    }

    private object Step10 {
        val acl = aclCatalog<User> {
            policy<Note> {
                allow(NoteOperation.Comment, NoteOperation.Publish, NoteOperation.Archive) { user, note -> user.owns(note) }
                allow(NoteOperation.Comment) { user, note -> user.wasSharedOn(note) }
            }
        }

        fun buttonLabel(operation: NoteOperation): String = when (operation) {
            NoteOperation.Comment -> "Add comment"
            NoteOperation.Publish -> "Publish"
            NoteOperation.Archive -> "Archive"
        }

        fun buttonsFor(user: User, note: Note): List<String> =
            listOf(NoteOperation.Comment, NoteOperation.Publish, NoteOperation.Archive)
                .filter { acl.can(user, it, note) }
                .map(::buttonLabel)
    }

    @Test
    fun step10_sealed_set_of_operations() = with(Step10) {
        assertEquals(listOf("Add comment", "Publish", "Archive"), buttonsFor(alice, draft))
        assertEquals(listOf("Add comment"), buttonsFor(carol, draft))
    }

    @Test
    fun step11_several_kinds_of_subjects() {
        val acl = aclCatalog<Principal> {
            policy<Note> {
                allow(Read, Write) { principal, note -> principal is Member && principal.user.owns(note) }
                allow(Read) { principal -> principal is ServiceAccount && "notes:read" in principal.scopes }
                allow(Read) { _, note -> note.isPublic }
            }
        }

        val indexer = ServiceAccount("search-indexer", scopes = setOf("notes:read"))

        assertTrue(acl.canWrite(Member(alice), draft))
        assertTrue(acl.canRead(indexer, draft))
        assertFalse(acl.canWrite(indexer, draft))
        assertTrue(acl.canRead(Anonymous, announcement))
        assertFalse(acl.canRead(Anonymous, draft))
    }

    @Test
    fun step12_resource_hierarchies() {
        val acl = aclCatalog<User> {
            policy<Attachment> {
                allow(Read, Write) { user, attachment -> user.id == attachment.noteOwnerId }
            }
            policy<Recording> {
                allow(Read) { user, recording -> user.id == recording.noteOwnerId }
                allow(Manage) { user, recording -> user.isAdmin && !recording.containsPersonalData }
            }
        }

        assertTrue(acl.canWrite(alice, Image("alice")))
        assertFalse(acl.canWrite(alice, Recording("alice", containsPersonalData = false)))
        assertTrue(acl.canRead(alice, Recording("alice", containsPersonalData = false)))
    }

    @Test
    fun step12_ambiguous_policies() {
        val acl = aclCatalog<User> {
            policy<Exportable> { allow(Read) { user -> user.isAdmin } }
            policy<Billable> { allow(Read) { user -> user.isAdmin } }
        }

        val decision = acl.decide(admin, Read, Invoice("acme"))
        assertEquals(AccessDecision.Denied(AmbiguousPolicy(Invoice::class, listOf(Exportable::class, Billable::class))), decision)
        assertEquals(
            "Ambiguous policies for ${Invoice::class.qualifiedName}: ${Exportable::class.qualifiedName}, " +
                "${Billable::class.qualifiedName}. Register a policy for ${Invoice::class.qualifiedName} to resolve it.",
            (decision as AccessDecision.Denied).reason.message,
        )

        val resolved = aclCatalog<User> {
            policy<Exportable> { allow(Read) { user -> user.isAdmin } }
            policy<Billable> { allow(Read) { user -> user.isAdmin } }
            policy<Invoice> { allow(Read) { user -> user.isAdmin } }
        }
        assertTrue(resolved.canRead(admin, Invoice("acme")))

        assertFailsWith<IllegalArgumentException> {
            aclCatalog<User> { policy<Any> { allow(Read) { true } } }
        }
    }

    private val appAcl = aclCatalog<User> {
        register(notePolicy)
        register(notebookPolicy)
        policy<Attachment> {
            allow(Read, Write) { user, attachment -> user.id == attachment.noteOwnerId }
        }
    }

    @Test
    fun step13_team_members_can_edit_team_notes() {
        assertTrue(appAcl.canWrite(bob, roadmap))
        assertFalse(appAcl.canWrite(carol, roadmap))
    }

    @Test
    fun step13_every_resource_type_has_a_policy() {
        assertTrue(appAcl.hasPolicyFor(Note::class))
        assertTrue(appAcl.hasPolicyFor(Notebook::class))
        assertTrue(appAcl.hasPolicyFor(Image::class))
        assertFalse(appAcl.hasPolicyFor(Invoice::class))
    }

    @Test
    fun step13_comparing_denials() {
        assertEquals(
            AccessDecision.Denied(NoMatchingAllowRule(Write, Note::class)),
            appAcl.decide(carol, Write, roadmap),
        )
    }

    @Test
    fun step14_putting_it_into_an_application() {
        val service = NoteService(step5Acl, mutableMapOf("roadmap" to roadmap, "draft" to draft))

        assertEquals(listOf(draft), service.visibleTo(carol))
        assertEquals(roadmap.copy(text = "Q3 roadmap v2"), service.edit(bob, "roadmap", "Q3 roadmap v2"))

        val denied = assertFailsWith<AccessDeniedException> { service.edit(carol, "roadmap", "hi") }
        assertEquals("No rule allows Write on ${Note::class.qualifiedName}", denied.message)
        assertEquals(NoMatchingAllowRule(Write, Note::class), denied.reason)
    }
}
