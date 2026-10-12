# ACL

`acl` is a small Kotlin library that answers one question well:

> Can subject `A` perform operation `X` on resource `B`?

- pure Kotlin, no framework dependencies
- one policy per resource type, written as a small DSL over your own domain types
- allow-only rules with default deny
- built-in `Read`, `Write` and `Manage` operations, plus your own; `Manage` implies all of them
- denials are values with a reason, not exceptions

## Installation

```kotlin
dependencies {
    implementation("io.liquidsoftware:acl:0.4.0-SNAPSHOT")
}
```

**Upgrading from 0.3?** Follow the [migration guide](docs/migrating-to-0.4.md).

This README describes the in-development `0.4.0` API. Until it is released, use a [local build](#using-a-local-build). The latest release on Maven Central, `0.3.0`, has the older API described in [CHANGELOG.md](CHANGELOG.md).

## Quick Start

```kotlin
import io.liquidsoftware.acl.AccessDecision
import io.liquidsoftware.acl.Operation.Manage
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import io.liquidsoftware.acl.aclCatalog

data class User(val id: String, val isSystemAdmin: Boolean)
data class Book(val userId: String)

val acl = aclCatalog<User> {
    policy<Book> {
        allow(Manage) { user -> user.isSystemAdmin }
        allow(Read, Write) { user, book -> user.id == book.userId }
    }
}

val bob = User(id = "bob", isSystemAdmin = false)
val admin = User(id = "root", isSystemAdmin = true)
val book = Book(userId = "bob")

acl.canRead(bob, book)      // true
acl.canWrite(bob, book)     // true
acl.canManage(admin, book)  // true

when (val decision = acl.decide(bob, Read, Book(userId = "alice"))) {
    AccessDecision.Granted -> println("granted")
    is AccessDecision.Denied -> println(decision.reason.message)  // "No matching allow rule"
}
```

The catalog is typed on the subject, so `acl.canRead("bob", book)` does not compile.

## Writing Rules

A rule names one or more operations and a predicate. Use a one-argument lambda (or `it`) when only the subject matters, and a two-argument lambda when the rule depends on the resource too:

```kotlin
policy<Book> {
    allow(Manage) { user -> user.isSystemAdmin }                 // subject only
    allow(Read, Write) { user, book -> user.id == book.userId }  // subject and resource
}
```

Any matching rule grants access. If no rule matches, the decision is `Denied(NoMatchingAllowRule)`. A rule for `Manage` also grants `Read`, `Write` and any custom operation.

Policies can be declared inline with `policy<R> { ... }` or built separately with `aclPolicy<User, Book> { ... }` and added with `register(policy)`, which is useful when a policy lives next to the resource it protects.

## Custom Operations

`Read`, `Write` and `Manage` are built in. Declare your own operations as objects:

```kotlin
import io.liquidsoftware.acl.Operation

data object Approve : Operation
data object Share : Operation

val acl = aclCatalog<User> {
    policy<Invoice> {
        allow(Manage) { user -> user.isSystemAdmin }
        allow(Approve) { user, invoice -> user.id == invoice.approverId }
    }
}

acl.can(bob, Approve, invoice)
acl.forSubject(bob).can(Share, invoice)
```

A custom operation covers only itself, and `Manage` covers every operation. To make one operation grant others, override `covers`:

```kotlin
data object Edit : Operation {
    override fun covers(requested: Operation) = requested == Edit || requested == Read || requested == Write
}
```

## Checking Many Resources

Bind the subject once with `forSubject`, then use Kotlin's collection functions:

```kotlin
val access = acl.forSubject(bob)

access.canRead(book)
books.filter(access::canRead)
val (editable, readOnly) = books.partition(access::canWrite)
books.all(access::canManage)
books.associateWith { access.decide(Read, it) }
```

## Type Hierarchies

Subjects can be any subtype of the catalog's subject type, so a sealed principal works as-is. Resources are routed to the policy registered for their most specific type, so subclasses and proxies fall back to their parent's policy unless they have their own:

```kotlin
sealed interface Principal { val id: String }
data class Member(override val id: String) : Principal
data class Admin(override val id: String) : Principal

open class Document(val ownerId: String)
class Contract(ownerId: String) : Document(ownerId)
class SecretDocument(ownerId: String) : Document(ownerId)

val acl = aclCatalog<Principal> {
    policy<Document> {
        allow(Manage) { it is Admin }
        allow(Read) { principal, doc -> principal.id == doc.ownerId }
    }
    policy<SecretDocument> {
        allow(Manage) { it is Admin }
    }
}

acl.canRead(Member("bob"), Contract("bob"))        // true, uses the Document policy
acl.canRead(Member("bob"), SecretDocument("bob"))  // false, SecretDocument has its own policy
```

If a resource matches two registered types and neither is a subtype of the other (for example, two interfaces it implements), the check throws `IllegalStateException`. A resource with no matching policy is denied with `NoPolicyRegistered`.

## Behavior

The following behavior is covered by tests:

- the catalog's subject type is checked at compile time
- subjects may be any subtype of the catalog's subject type
- resources route to the policy for their most specific registered type
- ambiguous routing fails fast; duplicate registration for one type is rejected
- one `allow` rule can grant several operations
- `Manage` implies every operation, including custom ones; other operations imply only themselves unless they override `covers`
- empty policies deny all access; resources with no policy are denied
- denied decisions carry a structured reason with a human-readable message

## Using a Local Build

To try unreleased changes from another Gradle project, either publish to your local Maven repository:

```bash
./gradlew publishToMavenLocal
```

and add `mavenLocal()` to the consuming project's repositories, or include this checkout as a composite build in the consumer's `settings.gradle.kts`:

```kotlin
includeBuild("../acl")
```

## More

- [docs/migrating-to-0.4.md](docs/migrating-to-0.4.md) explains how to upgrade from 0.3.
- [CHANGELOG.md](CHANGELOG.md) lists changes by release.
- [RELEASING.md](RELEASING.md) covers publishing to Maven Central.
- [docs/limitations-and-future-work.md](docs/limitations-and-future-work.md) tracks known limitations and ideas.
