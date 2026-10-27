# Denials as results

> Compiled, except the Arrow section: the rest is run by
> [`DenialsAsResultsRecipeTest`](../../src/test/kotlin/io/liquidsoftware/acl/recipes/results/DenialsAsResultsRecipeTest.kt).

The [tutorial](../tutorial.md#14-putting-it-into-an-application) turns a denial into an
exception at one place. If your services return results instead of throwing, `decide`
fits that style directly: a denial is already a value.

## A sealed result per use case

```kotlin
data class User(val id: String)
data class Note(val ownerId: String, val text: String, val sharedWith: Set<String> = emptySet())

val acl = aclCatalog<User> {
    policy<Note> {
        allow(Read, Write) { user, note -> user.id == note.ownerId }
        allow(Read) { user, note -> user.id in note.sharedWith }
    }
}

sealed interface EditResult {
    data class Edited(val note: Note) : EditResult
    data object NotFound : EditResult
    data class Forbidden(val reason: DenialReason) : EditResult
}

class NoteService(private val notes: MutableMap<String, Note>) {
    fun edit(user: User, noteId: String, text: String): EditResult {
        val note = notes[noteId] ?: return EditResult.NotFound
        return when (val decision = acl.decide(user, Write, note)) {
            AccessDecision.Granted -> EditResult.Edited(note.copy(text = text).also { notes[noteId] = it })
            // Don't confirm that a note exists to someone who may not even read it.
            is AccessDecision.Denied -> if (acl.canRead(user, note)) EditResult.Forbidden(decision.reason) else EditResult.NotFound
        }
    }
}
```

The `when` over `AccessDecision` is exhaustive, so there's no `else` to get wrong.

## 403 or 404?

The `Denied` branch above answers `Forbidden` only to users who can already see the note,
and `NotFound` to everyone else, so probing ids reveals nothing:

```kotlin
val service = NoteService(mutableMapOf("plan" to Note("alice", "Plan", sharedWith = setOf("bob"))))

service.edit(alice, "plan", "Plan v2")  // Edited
service.edit(bob, "plan", "hi")         // Forbidden(NoMatchingAllowRule(Write, Note::class)): bob can read it
service.edit(carol, "plan", "hi")       // NotFound: carol can't tell it exists
service.edit(alice, "missing", "hi")    // NotFound
```

The web layer then maps results to statuses in one `when`, with no exception handler:

```kotlin
fun EditResult.status(): Int = when (this) {
    is EditResult.Edited -> 200
    EditResult.NotFound -> 404
    is EditResult.Forbidden -> 403
}
```

Keep `reason.message` for logs, not for the response body: it names your resource types.

## With Arrow's `Raise`

> Not compiled: the core has no Arrow dependency. Written against Arrow 2.

If your services run inside `either { }` or another `Raise` scope, one small helper turns
a denial into a raised error, and the call site reads like a precondition:

```kotlin
data class AccessDenied(val reason: DenialReason)

fun <S : Any> Raise<AccessDenied>.ensureAccess(acl: AclCatalog<S>, subject: S, operation: Operation, resource: Any) {
    val decision = acl.decide(subject, operation, resource)
    if (decision is AccessDecision.Denied) raise(AccessDenied(decision.reason))
}

fun edit(user: User, note: Note, text: String): Either<AccessDenied, Note> = either {
    ensureAccess(acl, user, Write, note)
    note.copy(text = text)
}
```

When your use case has its own error type, have `AccessDenied` implement it, or map it
at the call with `withError({ denied -> EditError.Forbidden(denied.reason) }) { ... }`.
