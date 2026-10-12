# Migrating from 0.3 to 0.4

0.4 makes the catalog typed on its subject, replaces the collection helpers with a subject-bound view, moves everything into one package, and lets you declare your own operations. Most code migrates with mechanical edits. One behavior change (subtype routing) can grant access that 0.3 denied, so read [that section](#behavior-changes-to-review) before you ship.

The full list of changes is in [CHANGELOG.md](../CHANGELOG.md).

## Checklist

1. [Update the dependency](#1-update-the-dependency)
2. [Fix imports](#2-fix-imports)
3. [Give the catalog a subject type](#3-give-the-catalog-a-subject-type)
4. [Merge rules that repeat a predicate](#4-merge-rules-that-repeat-a-predicate) (optional)
5. [Replace the collection helpers](#5-replace-the-collection-helpers)
6. [Update code that treated `Operation` as an enum](#6-update-code-that-treated-operation-as-an-enum)
7. [Review the behavior changes](#behavior-changes-to-review)

## 1. Update the dependency

```kotlin
dependencies {
    implementation("io.liquidsoftware:acl:0.4.0")
}
```

## 2. Fix imports

Everything now lives in `io.liquidsoftware.acl`. The `catalog`, `decision` and `policy` subpackages are gone.

| 0.3 import | 0.4 import |
| --- | --- |
| `io.liquidsoftware.acl.catalog.aclCatalog` | `io.liquidsoftware.acl.aclCatalog` |
| `io.liquidsoftware.acl.catalog.AclCatalog` | `io.liquidsoftware.acl.AclCatalog` |
| `io.liquidsoftware.acl.policy.aclPolicy` | `io.liquidsoftware.acl.aclPolicy` |
| `io.liquidsoftware.acl.policy.AclPolicy` | `io.liquidsoftware.acl.AclPolicy` |
| `io.liquidsoftware.acl.decision.AccessDecision` | `io.liquidsoftware.acl.AccessDecision` |
| `io.liquidsoftware.acl.decision.NoMatchingAllowRule` | `io.liquidsoftware.acl.NoMatchingAllowRule` |
| `io.liquidsoftware.acl.decision.NoPolicyRegistered` | `io.liquidsoftware.acl.NoPolicyRegistered` |

A find-and-replace of `io.liquidsoftware.acl.catalog.`, `io.liquidsoftware.acl.decision.` and `io.liquidsoftware.acl.policy.` with `io.liquidsoftware.acl.` covers it.

`Operation` was already in `io.liquidsoftware.acl`. Static imports such as `import io.liquidsoftware.acl.Operation.Read` keep working.

## 3. Give the catalog a subject type

The subject type moves from each policy to the catalog. Inline policies only name the resource type.

**0.3**
```kotlin
val catalog = aclCatalog {
    policy<User, Book> {
        allow(Operation.Read) { user, book -> user.id == book.userId }
    }
    register(invoicePolicy)  // AclPolicy<User, Invoice>
}
```

**0.4**
```kotlin
val acl = aclCatalog<User> {
    policy<Book> {
        allow(Operation.Read) { user, book -> user.id == book.userId }
    }
    register(invoicePolicy)  // AclPolicy<User, Invoice>, unchanged
}
```

Standalone policies are unchanged: `aclPolicy<User, Book> { ... }` still takes both types.

The catalog's methods now take a subject of the catalog's type, so passing the wrong type is a compile error instead of a runtime `IllegalArgumentException`:

```kotlin
acl.canRead(user, book)      // fine
acl.canRead("bob", book)     // does not compile
```

### If one catalog served several subject types

In 0.3 a single catalog could hold `policy<User, Book>` and `policy<ServiceAccount, Report>`. In 0.4 a catalog has one subject type. Either give the subjects a common supertype:

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

or build one catalog per subject type.

## 4. Merge rules that repeat a predicate

Optional, but it removes duplication. `allow` now takes several operations:

**0.3**
```kotlin
allow(Operation.Read) { user, book -> user.id == book.userId }
allow(Operation.Write) { user, book -> user.id == book.userId }
```

**0.4**
```kotlin
allow(Operation.Read, Operation.Write) { user, book -> user.id == book.userId }
```

## 5. Replace the collection helpers

The 13 collection helpers and their result types (`BatchAccessDecision`, `ItemAccessDecision`, `AccessPartition`) are removed. Bind the subject with `forSubject` and use Kotlin's collection functions:

```kotlin
val access = acl.forSubject(bob)
```

| 0.3 | 0.4 |
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

The result types change accordingly:

- `AccessPartition` → `Pair<List<R>, List<R>>`: use `val (allowed, denied) = ...` instead of `.allowed` / `.denied`, and `denied.isEmpty()` instead of `.allGranted`.
- `BatchAccessDecision` → `List<Pair<R, AccessDecision>>`: `.allGranted` becomes `all { it.second.granted }`. If your resources are distinct, `books.associateWith { access.decide(op, it) }` gives a `Map` instead.

As before, `all` on an empty collection is `true`.

Single-resource checks are unchanged on the catalog (`acl.canRead(bob, book)`) and are also available on the bound view (`access.canRead(book)`).

## 6. Update code that treated `Operation` as an enum

`Operation` is now an interface, so you can declare your own operations:

```kotlin
data object Approve : Operation

policy<Invoice> {
    allow(Approve) { user, invoice -> user.id == invoice.approverId }
}
acl.can(bob, Approve, invoice)
```

`Operation.Read`, `Operation.Write` and `Operation.Manage` keep their names and behavior. What no longer compiles:

- `Operation.entries`, `Operation.values()`, `Operation.valueOf(...)`, `.name` and `.ordinal`
- an exhaustive `when (operation)` without an `else` branch

If you stored operations by name, map them yourself:

```kotlin
fun operationNamed(name: String): Operation = when (name) {
    "Read" -> Operation.Read
    "Write" -> Operation.Write
    "Manage" -> Operation.Manage
    else -> error("Unknown operation: $name")
}
```

`Manage` covers only `Read`, `Write` and itself, so a custom operation is granted only by rules that name it. To give admins `Approve` as well, write `allow(Manage, Approve) { ... }`. A custom operation covers only itself unless it overrides `covers`.

## Behavior changes to review

### Subtypes now route to their parent's policy

In 0.3 a resource matched a policy only if its runtime class was exactly the registered class. A subclass, interface implementation or ORM proxy found no policy and was denied with `NoPolicyRegistered`.

In 0.4 a resource routes to the policy registered for its most specific type. So if you have `policy<Document>` and check a `Contract : Document`, **0.3 denied it and 0.4 applies the `Document` policy**, which may grant access.

To check whether this affects you, list your registered resource types and look for subclasses or implementations of them that are checked at runtime (including Hibernate or other proxies). If one of them should keep its own rules, register a policy for it; the most specific policy wins. To keep denying it entirely, register an empty one:

```kotlin
policy<Contract> { }  // denies everything for Contract, regardless of the Document policy
```

### Subjects may be subtypes

In 0.3 a subject had to be exactly the policy's subject class, otherwise `decide` threw `IllegalArgumentException`. In 0.4 any subtype of the catalog's subject type is accepted, which is what makes sealed principals work.

### Ambiguous routing throws

If a resource matches two registered types and neither is a subtype of the other (for example `policy<Shareable>` and `policy<Archivable>`, and a class that implements both), the check throws `IllegalStateException` naming both types. Fix it by registering a policy for the concrete type. This is detected on the first check for that type, not when the catalog is built.

### Unchanged

- Allow-only rules with default deny.
- `Manage` implies `Read` and `Write`; `Read` and `Write` do not imply each other.
- `AccessDecision`, `NoMatchingAllowRule` and `NoPolicyRegistered` have the same shape and messages.
- Registering two policies for the same resource type still throws `IllegalStateException`.
