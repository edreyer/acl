# Lists and queries

> Compiled: every example here is run by
> [`ListsAndQueriesRecipeTest`](../../src/test/kotlin/io/liquidsoftware/acl/recipes/lists/ListsAndQueriesRecipeTest.kt).

The catalog checks resources you already have in memory. A list screen over a big table
can't load every row and filter, so the database has to narrow things down first. The
pattern: **narrow in the query, confirm with the catalog.**

## The rules

```kotlin
data class User(val id: String, val blockedBy: Set<String> = emptySet())

data class Note(
    val id: String,
    val ownerId: String,
    val isPublic: Boolean = false,
    val sharedWith: Set<String> = emptySet(),
)

val acl = aclCatalog<User> {
    policy<Note> {
        allow(Read, Write) { user, note -> user.id == note.ownerId }
        allow(Read) { user, note -> user.id in note.sharedWith }
        allow(Read) { user, note -> note.isPublic && note.ownerId !in user.blockedBy }
    }
}
```

## A query that is allowed to say too much

Write the query as a coarse version of the rules: it may return rows the user can't read,
but it must not leave out rows they can. Here it ignores blocking, which is awkward in SQL:

```kotlin
// Stands in for a table; readableCandidates is the WHERE clause.
class NoteQueries(private val rows: List<Note>) {
    fun readableCandidates(user: User): Sequence<Note> =
        rows.asSequence().filter { it.ownerId == user.id || user.id in it.sharedWith || it.isPublic }
}
```

Then let the catalog have the last word:

```kotlin
fun visibleNotes(user: User): List<Note> =
    queries.readableCandidates(user).filter(acl.forSubject(user)::canRead).toList()

visibleNotes(alice)  // n1 (hers), n2 (public), n4 (shared with her), n6 (public); not n3, mallory blocked her
```

If the query and the rules drift apart, this fails safe: an over-broad query costs some
wasted rows, never a leak. An over-narrow query hides notes the user should see, which a
test catches; nothing ever shows a note the catalog denies.

## Paging

Filtering a page after `LIMIT` gives short pages. Filter a stream of candidates and stop
when the page is full instead (in a real repository, the sequence fetches the next batch
of rows as it is consumed):

```kotlin
fun visiblePage(user: User, size: Int): List<Note> =
    queries.readableCandidates(user).filter(acl.forSubject(user)::canRead).take(size).toList()

visiblePage(alice, size = 3)  // n1, n2, n4: n3 is skipped, and the page is still full
```

The closer the query is to the rules, the fewer rows this reads; total counts ("page 1 of
12") come from the query and are an estimate unless the two match exactly.

## Decisions for the screen

Screens often need more than "visible": an edit button per row. Bind the subject once and
ask per item:

```kotlin
data class NoteView(val note: Note, val canEdit: Boolean)

fun noteList(user: User): List<NoteView> {
    val access = acl.forSubject(user)
    return visibleNotes(user).map { NoteView(it, canEdit = access.canWrite(it)) }
}
```

The button is a hint; the edit endpoint still checks `Write` itself.

## Load what the rules read

Rules run once per row, on the calling thread, and the library doesn't catch what they
throw. With an ORM:

- fetch what rules read (here `sharedWith`) with the query, for example a JPA fetch join
  or an Exposed join, rather than letting a rule trigger a lazy load per row
- check inside the transaction, or map entities to plain data classes first; a lazy
  relation touched after the session closes throws from `canRead`
