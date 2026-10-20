# ACL

`acl` is a small Kotlin library that answers one question well:

> Can subject `A` perform operation `X` on resource `B`?

- pure Kotlin, no framework dependencies
- one policy per resource type, written as a small DSL over your own domain types
- allow-only rules with default deny
- built-in `Read`, `Write` and `Manage` operations, plus your own; `Manage` implies `Read` and `Write`
- denials are values with a reason, not exceptions

## Installation

```kotlin
dependencies {
    implementation("io.liquidsoftware:acl:0.4.1")
}
```

Maven:

```xml
<dependency>
    <groupId>io.liquidsoftware</groupId>
    <artifactId>acl</artifactId>
    <version>0.4.1</version>
</dependency>
```

Requires JDK 17 or newer. (0.4.0 required JDK 21; use 0.4.1 or later on JDK 17.)

**Upgrading from 0.3?** Follow the [migration guide](docs/migrating-to-0.4.md).

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
    is AccessDecision.Denied -> println(decision.reason.message)  // "No rule allows Read on com.example.Book"
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

Any matching rule grants access. If no rule matches, the decision is `Denied(NoMatchingAllowRule(operation, resourceType))`. A rule for `Manage` also grants `Read` and `Write`.

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

acl.can(bob, Approve, invoice)            // true
acl.can(admin, Approve, invoice)          // false, Manage does not cover custom operations
acl.forSubject(bob).can(Share, invoice)   // false, no rule for Share
```

A custom operation is granted only by rules that name it, so adding one never widens what `Manage` grants. That keeps separation-of-duties rules like "admins can't approve invoices" intact. If a role should get both, name both:

```kotlin
allow(Manage, Approve) { user -> user.isSystemAdmin }
```

A custom operation covers only itself. To make one operation grant others, override `covers`:

```kotlin
data object Edit : Operation {
    override fun covers(requested: Operation) = requested == Edit || requested == Read || requested == Write
}
```

`covers` is not transitive. If `Super` covers `Edit` and `Edit` covers `Read`, a rule for `Super` grants `Read` only if `Super.covers(Read)` is itself true.

Operations are compared with `==`, so declare them as objects or data classes. An instance of a plain class only equals itself, so a check with a new instance is denied.

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

If a resource matches two registered types and neither is a subtype of the other (for example, two interfaces it implements), it is denied with `AmbiguousPolicy`, which names both types. Register a policy for the concrete type to resolve it. A resource with no matching policy is denied with `NoPolicyRegistered`.

`policy<Any>` is rejected when the catalog is built, because it would apply to every resource without its own policy and quietly replace default deny.

## Behavior

The following behavior is covered by tests:

- the catalog's subject type is checked at compile time
- subjects may be any subtype of the catalog's subject type
- resources route to the policy for their most specific registered type
- ambiguous routing is denied with `AmbiguousPolicy`; duplicate registration for one type and `policy<Any>` are rejected when the catalog is built
- one `allow` rule can grant several operations
- `Manage` implies `Read` and `Write` but not custom operations; other operations imply only themselves unless they override `covers`
- empty policies deny all access; resources with no policy are denied
- denied decisions carry a structured reason with a human-readable message

A catalog is immutable once built and safe to share between threads; it caches routing per resource class. Rules run on the calling thread, and the library does not catch exceptions they throw: a rule that throws (for example, by touching a lazy ORM relation outside its session) makes the check throw. Denials are never exceptions.

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
