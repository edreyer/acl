# Migrating from 0.3 to 0.5

0.4 and 0.5 change how a catalog is declared and checked:

- The catalog is typed on its subject.
- A subject-bound view replaces the collection helpers.
- Everything moves into one package.
- You can declare your own operations.
- Denials say which operation was refused on which type.
- `hasPolicyFor` lets tests check a catalog's wiring.

Most code migrates with mechanical edits. One behavior change, subtype routing, can grant access that 0.3 denied, so read [that section](#behavior-changes-to-review) before you ship.

Each step shows 0.3 code next to the 0.5 code that replaces it. The full list of changes is in [CHANGELOG.md](../CHANGELOG.md).

**Coming from 0.4?** Only steps 1, 7, 8 and 9 apply.

## Checklist

1. [Update the dependency](#1-update-the-dependency)
2. [Fix imports](#2-fix-imports)
3. [Give the catalog a subject type](#3-give-the-catalog-a-subject-type)
4. [Merge rules that repeat a predicate](#4-merge-rules-that-repeat-a-predicate) (optional)
5. [Replace the collection helpers](#5-replace-the-collection-helpers)
6. [Update code that treated `Operation` as an enum](#6-update-code-that-treated-operation-as-an-enum)
7. [Update code that matches `NoMatchingAllowRule`](#7-update-code-that-matches-nomatchingallowrule)
8. [Update code that reads denial messages](#8-update-code-that-reads-denial-messages)
9. [Check your catalog's wiring with `hasPolicyFor`](#9-check-your-catalogs-wiring-with-haspolicyfor) (optional)
10. [Review the behavior changes](#behavior-changes-to-review)

## 1. Update the dependency

**0.3**
```kotlin
dependencies {
    implementation("io.liquidsoftware:acl:0.3.0")
}
```

**0.5**
```kotlin
dependencies {
    implementation("io.liquidsoftware:acl:0.5.0")
}
```

0.5 runs on JDK 17 or newer. 0.3 needed JDK 21.

0.5 is built with Kotlin 2.4 and depends on `kotlin-stdlib` 2.4, so your project must compile with Kotlin 2.3 or newer. Older compilers can't read its metadata.

## 2. Fix imports

Everything now lives in `io.liquidsoftware.acl`. The `catalog`, `decision` and `policy` subpackages are gone.

**0.3**
```kotlin
import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.catalog.aclCatalog
import io.liquidsoftware.acl.decision.AccessDecision
import io.liquidsoftware.acl.decision.NoMatchingAllowRule
import io.liquidsoftware.acl.policy.aclPolicy
```

**0.5**
```kotlin
import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.aclCatalog
import io.liquidsoftware.acl.AccessDecision
import io.liquidsoftware.acl.NoMatchingAllowRule
import io.liquidsoftware.acl.aclPolicy
```

A find-and-replace of `io.liquidsoftware.acl.catalog.`, `io.liquidsoftware.acl.decision.` and `io.liquidsoftware.acl.policy.` with `io.liquidsoftware.acl.` covers it. Static imports such as `import io.liquidsoftware.acl.Operation.Read` keep working.

## 3. Give the catalog a subject type

The subject type moves from each policy to the catalog. Inline policies name only the resource type.

**0.3**
```kotlin
val catalog = aclCatalog {
    policy<User, Book> {
        allow(Operation.Read) { user, book -> user.id == book.userId }
    }
    register(invoicePolicy)  // AclPolicy<User, Invoice>
}
```

**0.5**
```kotlin
val acl = aclCatalog<User> {
    policy<Book> {
        allow(Operation.Read) { user, book -> user.id == book.userId }
    }
    register(invoicePolicy)  // AclPolicy<User, Invoice>, unchanged
}
```

Standalone policies are unchanged: `aclPolicy<User, Book> { ... }` still takes both types.

The catalog's methods now take a subject of the catalog's type, so passing the wrong type is a compile error instead of an `IllegalArgumentException` at runtime:

**0.3**
```kotlin
catalog.canRead(user, book)    // fine
catalog.canRead("bob", book)   // compiles, throws IllegalArgumentException
```

**0.5**
```kotlin
acl.canRead(user, book)        // fine
acl.canRead("bob", book)       // does not compile
```

### If one catalog served several subject types

In 0.3 a single catalog could hold policies for different subjects. In 0.5 a catalog has one subject type. Either give the subjects a common supertype, or build one catalog per subject type.

**0.3**
```kotlin
val catalog = aclCatalog {
    policy<User, Book> {
        allow(Operation.Read) { user, book -> user.id == book.userId }
    }
    policy<ServiceAccount, Report> {
        allow(Operation.Read) { _ -> true }
    }
}
```

**0.5**
```kotlin
sealed interface Principal
data class User(val id: String) : Principal
data class ServiceAccount(val name: String) : Principal

val acl = aclCatalog<Principal> {
    policy<Book> {
        allow(Operation.Read) { principal, book -> principal is User && principal.id == book.userId }
    }
    policy<Report> {
        allow(Operation.Read) { principal -> principal is ServiceAccount }
    }
}
```

## 4. Merge rules that repeat a predicate

This step is optional, but it removes duplication. `allow` now takes several operations.

**0.3**
```kotlin
allow(Operation.Read) { user, book -> user.id == book.userId }
allow(Operation.Write) { user, book -> user.id == book.userId }
```

**0.5**
```kotlin
allow(Operation.Read, Operation.Write) { user, book -> user.id == book.userId }
```

## 5. Replace the collection helpers

The 13 collection helpers and their result types (`BatchAccessDecision`, `ItemAccessDecision`, `AccessPartition`) are removed. Bind the subject with `forSubject` and use Kotlin's collection functions.

**0.3**
```kotlin
catalog.canReadAll(bob, books)
catalog.filterWritableBy(bob, books)

val partition = catalog.partitionReadableBy(bob, books)
partition.allowed
partition.denied
partition.allGranted

val batch = catalog.decideAll(bob, Operation.Read, books)
batch.allGranted
```

**0.5**
```kotlin
val access = acl.forSubject(bob)

books.all(access::canRead)
books.filter(access::canWrite)

val (allowed, denied) = books.partition(access::canRead)
allowed
denied
denied.isEmpty()

val decisions = books.map { it to access.decide(Operation.Read, it) }
decisions.all { it.second.granted }
```

The full mapping:

| 0.3 | 0.5 |
| --- | --- |
| `catalog.canReadAll(bob, books)` | `books.all(access::canRead)` |
| `catalog.canWriteAll(bob, books)` | `books.all(access::canWrite)` |
| `catalog.canManageAll(bob, books)` | `books.all(access::canManage)` |
| `catalog.canAll(bob, op, books)` | `books.all { access.can(op, it) }` |
| `catalog.filterReadableBy(bob, books)` | `books.filter(access::canRead)` |
| `catalog.filterWritableBy(bob, books)` | `books.filter(access::canWrite)` |
| `catalog.filterManageableBy(bob, books)` | `books.filter(access::canManage)` |
| `catalog.filterBy(bob, op, books)` | `books.filter { access.can(op, it) }` |
| `catalog.partitionReadableBy(bob, books)` | `books.partition(access::canRead)` |
| `catalog.partitionWritableBy(bob, books)` | `books.partition(access::canWrite)` |
| `catalog.partitionManageableBy(bob, books)` | `books.partition(access::canManage)` |
| `catalog.partitionBy(bob, op, books)` | `books.partition { access.can(op, it) }` |
| `catalog.decideAll(bob, op, books)` | `books.map { it to access.decide(op, it) }` |

If your resources are distinct, `books.associateWith { access.decide(op, it) }` gives a `Map` instead of a list of pairs. As before, `all` on an empty collection is `true`.

Single-resource checks are unchanged on the catalog (`acl.canRead(bob, book)`). They are also available on the bound view (`access.canRead(book)`).

## 6. Update code that treated `Operation` as an enum

`Operation` is now an interface, so you can declare your own operations. `Operation.Read`, `Operation.Write` and `Operation.Manage` keep their names and behavior.

These no longer compile:

- `Operation.entries`, `Operation.values()`, `Operation.valueOf(...)`, `.name` and `.ordinal`
- an exhaustive `when (operation)` without an `else` branch

**0.3**
```kotlin
val operation = Operation.valueOf(name)

when (operation) {
    Operation.Read -> "read"
    Operation.Write -> "write"
    Operation.Manage -> "manage"
}
```

**0.5**
```kotlin
fun operationNamed(name: String): Operation = when (name) {
    "Read" -> Operation.Read
    "Write" -> Operation.Write
    "Manage" -> Operation.Manage
    else -> error("Unknown operation: $name")
}

val operation = operationNamed(name)

when (operation) {
    Operation.Read -> "read"
    Operation.Write -> "write"
    Operation.Manage -> "manage"
    else -> "custom"
}
```

A custom operation is a plain object:

```kotlin
data object Approve : Operation

policy<Invoice> {
    allow(Approve) { user, invoice -> user.id == invoice.approverId }
}
acl.can(bob, Approve, invoice)
```

To keep a `when` exhaustive without `else`, match on a sealed set of your own operations instead of on `Operation`:

```kotlin
sealed interface InvoiceOperation : Operation {
    data object Approve : InvoiceOperation
    data object Share : InvoiceOperation
}

when (operation) {  // operation: InvoiceOperation
    InvoiceOperation.Approve -> "approved"
    InvoiceOperation.Share -> "shared"
}
```

The built-in `Read`, `Write` and `Manage` can't join that set, so a `when` that also matches them still needs an `else`.

In 0.3 `Manage` covered every operation. In 0.5 it covers only `Read`, `Write` and itself, so a custom operation is granted only by rules that name it. To give admins `Approve` as well, write `allow(Manage, Approve) { ... }`. A custom operation covers only itself unless it overrides `covers`.

## 7. Update code that matches `NoMatchingAllowRule`

`NoMatchingAllowRule` was an object. It is now a data class carrying the requested `operation` and the resource's runtime `resourceType`.

**0.3**
```kotlin
val decision = catalog.decide(bob, Operation.Write, alicesBook)

if (decision == AccessDecision.Denied(NoMatchingAllowRule)) {
    log.info("Rule denied the write")
}

when (val reason = (decision as AccessDecision.Denied).reason) {
    NoMatchingAllowRule -> respondForbidden()
    is NoPolicyRegistered -> alertMissingPolicy(reason.resourceType)
}
```

**0.5**
```kotlin
val decision = acl.decide(bob, Operation.Write, alicesBook)

if (decision is AccessDecision.Denied && decision.reason is NoMatchingAllowRule) {
    log.info("Rule denied the write")
}

when (val reason = (decision as AccessDecision.Denied).reason) {
    is NoMatchingAllowRule -> respondForbidden()
    is NoPolicyRegistered -> alertMissingPolicy(reason.resourceType)
    is AmbiguousPolicy -> alertAmbiguous(reason.candidates)
}
```

`AmbiguousPolicy` is a new reason (see [behavior changes](#ambiguous-routing-is-denied)), so an exhaustive `when` needs a branch for it.

The reason now says what was denied:

```kotlin
val reason = (decision as AccessDecision.Denied).reason as NoMatchingAllowRule
reason.operation     // Operation.Write
reason.resourceType  // Book::class
```

`resourceType` is the resource's runtime class. When a `policy<Document>` handles a `Contract`, it is `Contract::class`.

### In tests

**0.3**
```kotlin
assertEquals(AccessDecision.Denied(NoMatchingAllowRule), catalog.decide(bob, Operation.Write, alicesBook))
```

**0.5**
```kotlin
assertEquals(
    AccessDecision.Denied(NoMatchingAllowRule(Operation.Write, Book::class)),
    acl.decide(bob, Operation.Write, alicesBook),
)
```

## 8. Update code that reads denial messages

`message` and `toString()` of `NoMatchingAllowRule` now name the operation and type. Update any log assertions or alert rules that match the old text.

**0.3**
```kotlin
NoMatchingAllowRule.message  // "No matching allow rule"
```

**0.5**
```kotlin
NoMatchingAllowRule(Operation.Write, Book::class).message  // "No rule allows Write on com.example.Book"
```

`NoPolicyRegistered` keeps its message.

## 9. Check your catalog's wiring with `hasPolicyFor`

This step is optional, but recommended. A resource type with no policy is denied like any other check, so in 0.3 the only way to catch a missing policy in a test was to decide on a sample resource and inspect the reason.

**0.3**
```kotlin
@Test
fun contracts_have_a_policy() {
    val decision = catalog.decide(bob, Operation.Read, Contract(ownerId = "bob"))
    assertFalse(decision is AccessDecision.Denied && decision.reason is NoPolicyRegistered)
}
```

**0.5**
```kotlin
@Test
fun contracts_have_a_policy() {
    assertTrue(acl.hasPolicyFor(Contract::class))
}
```

`hasPolicyFor` is true only when the type routes to exactly one policy, its own or a supertype's. It is false both for a type with no policy and for an ambiguous one.

## Behavior changes to review

### Subtypes now route to their parent's policy

In 0.3 a resource matched a policy only if its runtime class was exactly the registered class. A subclass, an interface implementation or an ORM proxy found no policy and was denied with `NoPolicyRegistered`.

In 0.5 a resource routes to the policy registered for its most specific type. Take `policy<Document>` and a check on a `Contract : Document`: **0.3 denied it, and 0.5 applies the `Document` policy**, which may grant access.

**0.3**
```kotlin
val catalog = aclCatalog {
    policy<User, Document> {
        allow(Operation.Read) { user, doc -> user.id == doc.ownerId }
    }
}
catalog.canRead(bob, Contract(ownerId = "bob"))  // false: NoPolicyRegistered
```

**0.5**
```kotlin
val acl = aclCatalog<User> {
    policy<Document> {
        allow(Operation.Read) { user, doc -> user.id == doc.ownerId }
    }
}
acl.canRead(bob, Contract(ownerId = "bob"))  // true: the Document policy applies
```

To check whether this affects you, list your registered resource types. Look for subclasses or implementations of them that are checked at runtime, including Hibernate or other proxies.

If one of them should keep its own rules, register a policy for it: the most specific policy wins. To keep denying it entirely, register an empty one:

```kotlin
policy<Contract> { }  // denies everything for Contract, whatever the Document policy allows
```

### Subjects may be subtypes

In 0.3 a subject had to be exactly the policy's subject class, or `decide` threw `IllegalArgumentException`. In 0.5 any subtype of the catalog's subject type is accepted, which is what makes sealed principals work.

### Ambiguous routing is denied

A resource can match two registered types where neither is a subtype of the other. Take `policy<Shareable>` and `policy<Archivable>` and a class that implements both. Such a check is denied with `AmbiguousPolicy`, which names both types. Fix it by registering a policy for the concrete type. Checks never throw for this.

### `policy<Any>` is rejected

Because of subtype routing, a policy for `Any` would apply to every resource that has no policy of its own and replace default deny. Registering one throws `IllegalArgumentException` when the catalog is built.

### Unchanged

- Rules are allow-only and anything not allowed is denied.
- `Manage` implies `Read` and `Write`, and `Read` and `Write` do not imply each other.
- `AccessDecision` and `NoPolicyRegistered` have the same shape and messages.
- Registering two policies for the same resource type still throws `IllegalStateException`.
