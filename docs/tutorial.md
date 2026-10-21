# Tutorial

This tutorial builds the access rules for a small note-taking app, one step at a time. Each step adds one idea to the step before it, so you can stop at the step that covers what you need, or read to the end for the whole library.

Every example here is compiled and run by [`TutorialExamplesTest`](../src/test/kotlin/io/liquidsoftware/acl/tutorial/TutorialExamplesTest.kt), so the results in the comments are the results you will get.

1. [Your first catalog](#1-your-first-catalog)
2. [More operations, more rules](#2-more-operations-more-rules)
3. [Rules about the subject alone, and `Manage`](#3-rules-about-the-subject-alone-and-manage)
4. [Asking why: `decide`](#4-asking-why-decide)
5. [Rules from your own domain](#5-rules-from-your-own-domain)
6. [More resource types, and policies in their own files](#6-more-resource-types-and-policies-in-their-own-files)
7. [Checking many resources](#7-checking-many-resources)
8. [Your own operations](#8-your-own-operations)
9. [Operations that imply others](#9-operations-that-imply-others)
10. [A sealed set of operations](#10-a-sealed-set-of-operations)
11. [Several kinds of subjects](#11-several-kinds-of-subjects)
12. [Resource hierarchies](#12-resource-hierarchies)
13. [Testing your catalog](#13-testing-your-catalog)
14. [Putting it into an application](#14-putting-it-into-an-application)

## Setup

Add the dependency:

```kotlin
dependencies {
    implementation("io.liquidsoftware:acl:0.5.0")
}
```

The library needs JDK 17 or newer and Kotlin 2.3 or newer. Everything lives in the `io.liquidsoftware.acl` package. The examples assume these imports:

```kotlin
import io.liquidsoftware.acl.*
import io.liquidsoftware.acl.Operation.Manage
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
```

## 1. Your first catalog

The library answers one question: can a **subject** perform an **operation** on a **resource**? The subject is whoever is asking (usually a user), the resource is the thing they want to touch, and the operation is what they want to do with it.

Subjects and resources are your own classes. The library never asks you to implement an interface or extend a base class:

```kotlin
data class User(val id: String)
data class Note(val ownerId: String, val text: String)
```

A **catalog** holds the rules. It is typed on the subject, and holds one **policy** per resource type. A policy is a list of `allow` rules:

```kotlin
val acl = aclCatalog<User> {
    policy<Note> {
        allow(Read) { user, note -> user.id == note.ownerId }
    }
}
```

Read it aloud: "for notes, allow `Read` when the user owns the note". Now ask the catalog:

```kotlin
val alice = User("alice")
val bob = User("bob")
val groceries = Note(ownerId = "alice", text = "milk, eggs")

acl.canRead(alice, groceries)   // true
acl.canRead(bob, groceries)     // false, bob doesn't own it
acl.canWrite(alice, groceries)  // false, no rule allows Write
```

The last line shows the most important rule of the library: **anything no rule allows is denied**. Rules only ever allow. There is no `deny` rule to forget, and nothing is allowed by accident.

Because the catalog is typed on `User`, passing anything else as the subject is a compile error: `acl.canRead("alice", groceries)` doesn't compile.

## 2. More operations, more rules

One rule can allow several operations, and a policy can have as many rules as you like. Let's let owners edit their notes, and let anyone read a note marked public:

```kotlin
data class Note(val ownerId: String, val text: String, val isPublic: Boolean = false)

val acl = aclCatalog<User> {
    policy<Note> {
        allow(Read, Write) { user, note -> user.id == note.ownerId }
        allow(Read) { _, note -> note.isPublic }
    }
}

val announcement = Note(ownerId = "alice", text = "Office closed Friday", isPublic = true)

acl.canWrite(alice, groceries)    // true, the first rule allows Write
acl.canRead(bob, announcement)    // true, the second rule matches
acl.canWrite(bob, announcement)   // false, public notes are only readable
acl.canRead(bob, groceries)       // false, neither rule matches
```

(`alice`, `bob` and `groceries` are the same as in step 1.)

Access is granted when **any** rule for the operation matches, so rules add up. The order of the rules doesn't matter.

A rule's lambda receives the subject and the resource. Use `_` for the one you don't need, as the public-note rule does with the subject.

## 3. Rules about the subject alone, and `Manage`

Some rules only care about who is asking. Give `allow` a one-argument lambda and it receives only the subject. Let's add administrators:

```kotlin
data class User(val id: String, val isAdmin: Boolean = false)

val acl = aclCatalog<User> {
    policy<Note> {
        allow(Manage) { user -> user.isAdmin }
        allow(Read, Write) { user, note -> user.id == note.ownerId }
        allow(Read) { _, note -> note.isPublic }
    }
}

val admin = User("root", isAdmin = true)

acl.canManage(admin, groceries)  // true
acl.canRead(admin, groceries)    // true, Manage covers Read
acl.canWrite(admin, groceries)   // true, Manage covers Write
acl.canManage(alice, groceries)  // false, owning a note isn't managing it
```

(`alice` and `groceries` are as before, with the new `User` type.)

The library has three built-in operations: `Read`, `Write` and `Manage`. A rule for `Manage` also grants `Read` and `Write`, so you don't have to list all three for an administrator. `Read` and `Write` grant only themselves.

The single-argument form also works with `it`: `allow(Manage) { it.isAdmin }`.

## 4. Asking why: `decide`

`can`, `canRead`, `canWrite` and `canManage` return a `Boolean`, which is all most call sites need. When you need to know *why* access was denied, for a log line, an error message or an audit trail, call `decide` instead. It returns an `AccessDecision`, a sealed type with two cases:

```kotlin
when (val decision = acl.decide(bob, Write, groceries)) {
    AccessDecision.Granted -> println("granted")
    is AccessDecision.Denied -> println(decision.reason.message)  // "No rule allows Write on com.example.Note"
}
```

Messages use the fully qualified class name; the examples assume your classes live in `com.example`.

A denial carries a `DenialReason`, which is also sealed, so you can handle each case without an `else`:

```kotlin
fun explain(decision: AccessDecision): String = when (decision) {
    AccessDecision.Granted -> "granted"
    is AccessDecision.Denied -> when (val reason = decision.reason) {
        is NoMatchingAllowRule -> "you may not ${reason.operation} this ${reason.resourceType.simpleName}"
        is NoPolicyRegistered -> "bug: no policy for ${reason.resourceType.simpleName}"
        is AmbiguousPolicy -> "bug: ${reason.message}"
    }
}

explain(acl.decide(alice, Read, groceries))  // "granted"
explain(acl.decide(bob, Write, groceries))   // "you may not Write this Note"
```

The three reasons mean different things:

- `NoMatchingAllowRule(operation, resourceType)` is the normal "no": the policy ran and no rule allowed this operation. It names the operation that was refused and the resource's runtime class.
- `NoPolicyRegistered(resourceType)` means the catalog has no policy for this kind of resource at all. That is almost always a missing policy, not an intended denial.
- `AmbiguousPolicy` comes up in [step 12](#12-resource-hierarchies).

For example, we haven't written a policy for notebooks yet:

```kotlin
data class Notebook(val ownerId: String, val title: String)

explain(acl.decide(alice, Read, Notebook("alice", "Recipes")))  // "bug: no policy for Notebook"
```

A check never throws because access is denied. Denials are values you can return, log or turn into an HTTP status.

## 5. Rules from your own domain

Rules are plain Kotlin, so they can use anything your types know. Real apps grow sharing and teams, and the cleanest way to keep the policy readable is to give your domain types small helper functions and keep the policy itself one line per rule.

From here on the examples use these types:

```kotlin
data class User(
    val id: String,
    val isAdmin: Boolean = false,
    val teams: Set<String> = emptySet(),
)

data class Note(
    val ownerId: String,
    val text: String,
    val isPublic: Boolean = false,
    val teamId: String? = null,
    val sharedWith: Set<String> = emptySet(),
)

fun User.owns(note: Note) = id == note.ownerId
fun User.isOnTeamOf(note: Note) = note.teamId != null && note.teamId in teams
fun User.wasSharedOn(note: Note) = id in note.sharedWith
```

```kotlin
val acl = aclCatalog<User> {
    policy<Note> {
        allow(Manage) { user -> user.isAdmin }
        allow(Read, Write) { user, note -> user.owns(note) }
        allow(Read, Write) { user, note -> user.isOnTeamOf(note) }
        allow(Read) { user, note -> user.wasSharedOn(note) }
        allow(Read) { _, note -> note.isPublic }
    }
}

val alice = User("alice", teams = setOf("design"))
val bob = User("bob", teams = setOf("design"))
val carol = User("carol")
val admin = User("root", isAdmin = true)

val roadmap = Note(ownerId = "alice", text = "Q3 roadmap", teamId = "design")
val draft = Note(ownerId = "alice", text = "Draft", sharedWith = setOf("carol"))

acl.canWrite(bob, roadmap)   // true, bob is on the design team
acl.canRead(carol, roadmap)  // false, carol isn't on the team
acl.canRead(carol, draft)    // true, the draft was shared with carol
acl.canWrite(carol, draft)   // false, sharing grants Read only
```

Each rule says one thing, so the policy doubles as documentation of who can do what.

## 6. More resource types, and policies in their own files

A catalog holds one policy per resource type. Add a policy for notebooks next to the one for notes:

```kotlin
data class Notebook(val ownerId: String, val title: String)

val acl = aclCatalog<User> {
    policy<Note> { /* as in step 5 */ }
    policy<Notebook> {
        allow(Manage) { user -> user.isAdmin }
        allow(Read, Write) { user, notebook -> user.id == notebook.ownerId }
    }
}
```

Each resource is checked against the policy for its own type, so a `Notebook` never runs a `Note` rule.

As the app grows, you may prefer to keep each policy next to the resource it protects. Build a policy on its own with `aclPolicy<Subject, Resource>`, and add it to the catalog with `register`:

```kotlin
// Notebook.kt
val notebookPolicy = aclPolicy<User, Notebook> {
    allow(Manage) { user -> user.isAdmin }
    allow(Read, Write) { user, notebook -> user.id == notebook.ownerId }
}

// Acl.kt
val acl = aclCatalog<User> {
    policy<Note> { /* as in step 5 */ }
    register(notebookPolicy)
}

acl.canWrite(alice, Notebook("alice", "Recipes"))  // true
acl.canRead(bob, Notebook("alice", "Recipes"))     // false
```

Both forms build the same thing; pick whichever reads better. Registering two policies for the same resource type throws when the catalog is built, so a policy can't be silently replaced.

## 7. Checking many resources

Screens usually show lists: all the notes a user can see, the ones they can edit, and so on. Bind the subject once with `forSubject`, and the checks become plain functions that work with Kotlin's collection functions:

Using the step 5 catalog, plus the public note from step 2 written with the step 5 types:

```kotlin
val announcement = Note(ownerId = "alice", text = "Office closed Friday", isPublic = true)
val notes = listOf(roadmap, draft, announcement)
val access = acl.forSubject(carol)

notes.filter(access::canRead)                                 // [draft, announcement]
val (editable, readOnly) = notes.partition(access::canWrite)  // editable is empty, readOnly has all three
notes.any(access::canWrite)                                   // false
notes.associateWith { access.decide(Write, it) }              // each note mapped to its decision
```

`SubjectAccess` has the same checks as the catalog (`can`, `canRead`, `canWrite`, `canManage`, `decide`), just without the subject argument.

## 8. Your own operations

`Read`, `Write` and `Manage` cover a lot, but most apps have actions that don't fit them: commenting, publishing, approving. Declare your own operations as objects that implement `Operation`:

```kotlin
data object Comment : Operation
data object Publish : Operation

val acl = aclCatalog<User> {
    policy<Note> {
        allow(Manage) { user -> user.isAdmin }
        allow(Read, Write, Comment, Publish) { user, note -> user.owns(note) }
        allow(Read, Comment) { user, note -> user.wasSharedOn(note) }
    }
}

acl.can(carol, Comment, draft)   // true, the draft was shared with carol
acl.can(carol, Publish, draft)   // false, only the owner can publish
acl.can(alice, Publish, draft)   // true
acl.can(admin, Publish, draft)   // false, Manage doesn't cover custom operations
```

Use `can` (or `decide`) with a custom operation; `canRead` and friends are shortcuts for the built-ins.

The last line is deliberate. `Manage` covers only `Read`, `Write` and `Manage`, never your own operations. Adding a new operation therefore never widens what an administrator can already do, which keeps separation-of-duties rules ("admins can't publish on someone's behalf") intact. When a role should get both, say so:

```kotlin
allow(Manage, Publish) { user -> user.isAdmin }
```

Operations are compared with `==`, so declare them as `object`s (or data classes). An instance of a plain class only equals itself, so a check with a fresh instance would be denied.

## 9. Operations that imply others

By default an operation grants only itself. To make one operation grant others the way `Manage` does, override `covers`. Here a `Contribute` operation lets team members read and comment on a team's notes without being able to edit them. It replaces the team rule from step 5, which allowed `Read` and `Write`:

```kotlin
data object Contribute : Operation {
    override fun covers(requested: Operation) =
        requested == Contribute || requested == Read || requested == Comment
}

val acl = aclCatalog<User> {
    policy<Note> {
        allow(Read, Write, Comment, Publish) { user, note -> user.owns(note) }
        allow(Contribute) { user, note -> user.isOnTeamOf(note) }
    }
}

acl.canRead(bob, roadmap)           // true, Contribute covers Read
acl.can(bob, Comment, roadmap)      // true, Contribute covers Comment
acl.canWrite(bob, roadmap)          // false, Contribute doesn't cover Write
acl.can(bob, Contribute, roadmap)   // true
```

`covers` answers "does a rule for me also allow `requested`?". It isn't transitive: if `Super` covers `Contribute` and `Contribute` covers `Read`, a rule for `Super` grants `Read` only if `Super.covers(Read)` is itself true. Spell out everything an operation grants.

## 10. A sealed set of operations

`Operation` is an open interface, so a `when` over an `Operation` always needs an `else` branch. When you want the compiler to tell you about every place that must handle a new operation, group your operations under a sealed interface that extends `Operation`:

```kotlin
sealed interface NoteOperation : Operation {
    data object Comment : NoteOperation
    data object Publish : NoteOperation
    data object Archive : NoteOperation
}

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
}  // no else: adding a NoteOperation is a compile error here until it is handled

fun buttonsFor(user: User, note: Note): List<String> =
    listOf(NoteOperation.Comment, NoteOperation.Publish, NoteOperation.Archive)
        .filter { acl.can(user, it, note) }
        .map(::buttonLabel)

buttonsFor(alice, draft)  // ["Add comment", "Publish", "Archive"]
buttonsFor(carol, draft)  // ["Add comment"]
```

Everywhere else these are ordinary operations: rules and checks take them like any other `Operation`. The built-in `Read`, `Write` and `Manage` can't join your sealed set, so a `when` that also matches them still needs an `else`.

## 11. Several kinds of subjects

Not every caller is a person. A catalog's subject can be any type, including a sealed hierarchy, and every check accepts any subtype of it. Rules use `is` to tell the kinds apart, and Kotlin's smart casts do the rest:

```kotlin
sealed interface Principal

data class Member(val user: User) : Principal
data class ServiceAccount(val name: String, val scopes: Set<String>) : Principal
data object Anonymous : Principal

val acl = aclCatalog<Principal> {
    policy<Note> {
        allow(Read, Write) { principal, note -> principal is Member && principal.user.owns(note) }
        allow(Read) { principal -> principal is ServiceAccount && "notes:read" in principal.scopes }
        allow(Read) { _, note -> note.isPublic }
    }
}

val indexer = ServiceAccount("search-indexer", scopes = setOf("notes:read"))

acl.canWrite(Member(alice), draft)   // true
acl.canRead(indexer, draft)          // true, it has the notes:read scope
acl.canWrite(indexer, draft)         // false
acl.canRead(Anonymous, announcement) // true, the note is public
acl.canRead(Anonymous, draft)        // false
```

Default deny applies here too: a kind of principal that no rule mentions gets nothing, so adding a new one never grants it access until a rule says so. And because `Principal` is sealed, your own `when (principal)` code stays exhaustive.

## 12. Resource hierarchies

Resources can form hierarchies too. A resource is checked against the policy for its **most specific** registered type, so subtypes share their parent's policy unless they have one of their own:

```kotlin
open class Attachment(val noteOwnerId: String)
class Image(noteOwnerId: String) : Attachment(noteOwnerId)
class Recording(noteOwnerId: String, val containsPersonalData: Boolean) : Attachment(noteOwnerId)

val acl = aclCatalog<User> {
    policy<Attachment> {
        allow(Read, Write) { user, attachment -> user.id == attachment.noteOwnerId }
    }
    policy<Recording> {
        allow(Read) { user, recording -> user.id == recording.noteOwnerId }
        allow(Manage) { user, recording -> user.isAdmin && !recording.containsPersonalData }
    }
}

acl.canWrite(alice, Image("alice"))                                  // true, uses the Attachment policy
acl.canWrite(alice, Recording("alice", containsPersonalData = false)) // false, Recording's own policy only lets owners Read
```

This also means proxies and generated subclasses (from an ORM, say) are checked against the policy for the class they extend.

A resource can match two policies where neither type is more specific than the other, typically two interfaces it implements. The library won't guess between them; the check is denied with `AmbiguousPolicy`, which names both candidates:

```kotlin
interface Exportable
interface Billable
class Invoice(val customerId: String) : Exportable, Billable

val acl = aclCatalog<User> {
    policy<Exportable> { allow(Read) { user -> user.isAdmin } }
    policy<Billable> { allow(Read) { user -> user.isAdmin } }
}

val decision = acl.decide(admin, Read, Invoice("acme"))
// Denied(AmbiguousPolicy(Invoice::class, candidates = [Exportable::class, Billable::class]))
// decision.reason.message: "Ambiguous policies for com.example.Invoice: com.example.Exportable,
//   com.example.Billable. Register a policy for com.example.Invoice to resolve it."
```

Registering `policy<Invoice> { ... }` resolves it, because `Invoice` is more specific than both.

One type is off limits: `policy<Any>` throws when the catalog is built. It would match every resource that has no policy of its own and quietly replace default deny.

## 13. Testing your catalog

Policies are just values, so test them like any other code: build the catalog your app uses and assert what each kind of user may do. Say the app's catalog combines the policies from the earlier steps:

```kotlin
val acl = aclCatalog<User> {
    policy<Note> { /* as in step 5 */ }
    register(notebookPolicy)
    policy<Attachment> {
        allow(Read, Write) { user, attachment -> user.id == attachment.noteOwnerId }
    }
}
```

```kotlin
@Test
fun team_members_can_edit_team_notes() {
    assertTrue(acl.canWrite(bob, roadmap))
    assertFalse(acl.canWrite(carol, roadmap))
}
```

A forgotten policy is hard to spot, because through `canRead` it looks like any other "no". Assert the wiring directly with `hasPolicyFor`, which is true when a type routes to exactly one policy, its own or a supertype's:

```kotlin
@Test
fun every_resource_type_has_a_policy() {
    assertTrue(acl.hasPolicyFor(Note::class))
    assertTrue(acl.hasPolicyFor(Notebook::class))
    assertTrue(acl.hasPolicyFor(Image::class))   // routes to the Attachment policy
}
```

And when a test needs the reason for a denial, compare the decision directly; reasons are data classes:

```kotlin
assertEquals(
    AccessDecision.Denied(NoMatchingAllowRule(Write, Note::class)),
    acl.decide(carol, Write, roadmap),
)
```

Configuration mistakes surface when the catalog is built, not on the first check: registering two policies for one type, or a `policy<Any>`, throws from `aclCatalog { }`. A test that just builds your catalog catches them.

## 14. Putting it into an application

The library has no opinion about frameworks, so the last step is a few lines of your own glue. A typical shape is:

- build the catalog **once** at startup and share it; a catalog is immutable and safe to use from many threads
- load the resource, then check it, then act
- turn a denial into whatever your app uses for "forbidden" at one place

```kotlin
class AccessDeniedException(val reason: DenialReason) : RuntimeException(reason.message)

fun <S : Any> AclCatalog<S>.requireAccess(subject: S, operation: Operation, resource: Any) {
    val decision = decide(subject, operation, resource)
    if (decision is AccessDecision.Denied) throw AccessDeniedException(decision.reason)
}

class NoteService(private val acl: AclCatalog<User>, private val notes: MutableMap<String, Note>) {
    fun visibleTo(user: User): List<Note> =
        notes.values.filter(acl.forSubject(user)::canRead)

    fun edit(user: User, noteId: String, text: String): Note {
        val note = notes.getValue(noteId)
        acl.requireAccess(user, Write, note)
        return note.copy(text = text).also { notes[noteId] = it }
    }
}

val service = NoteService(acl, mutableMapOf("roadmap" to roadmap, "draft" to draft))

service.visibleTo(carol)                       // [draft]
service.edit(bob, "roadmap", "Q3 roadmap v2")  // returns the updated note
service.edit(carol, "roadmap", "hi")           // throws AccessDeniedException: "No rule allows Write on com.example.Note"
```

The exception is yours, not the library's: a web layer can map `AccessDeniedException` to a 403 (or a 404, if you'd rather not reveal that the note exists) in one handler, and `reason.message` is ready for the log.

Two things to keep in mind:

- Rules run on the calling thread, and the library doesn't catch exceptions they throw. A rule that touches a lazily loaded relation outside its database session will throw from the check. Load what the rules need before you check.
- Keep rules cheap. A list screen runs them once per item, so a rule that makes a database call per note turns into N queries. Put the data rules need on the resource or the subject.

## Where next

- The [README](../README.md) is the short reference for everything covered here.
- [Migrating to 0.5](migrating-to-0.5.md) helps if you have code written against 0.3 or 0.4.
- [Limitations and future work](limitations-and-future-work.md) lists what the library deliberately doesn't do yet.
