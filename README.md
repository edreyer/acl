# ACL

`acl` is a small Kotlin ACL library for answering one question well:

Can subject `A` access resource `B`?

The library is intentionally small:

- pure ACL core
- allow-only rules
- `Manage` implies `Read` and `Write`
- type-aware resource routing (subtypes use the most specific registered policy)
- subject-bound checks that compose with Kotlin collections

## Installation

```kotlin
dependencies {
    implementation("io.liquidsoftware:acl:0.3.0-SNAPSHOT")
}
```

## Local Use

To use this snapshot in another Gradle project, you can either:

1. Publish it to your local Maven cache:
```bash
./gradlew publishToMavenLocal
```

Then add `mavenLocal()` to the consuming project repositories and depend on:
```kotlin
implementation("io.liquidsoftware:acl:0.3.0-SNAPSHOT")
```

If you want to refresh the cached snapshot after a new local publish, run the consuming build with:
```bash
./gradlew --refresh-dependencies <task>
```

2. Use a composite build without publishing:
```kotlin
includeBuild("/Users/erikdreyer/dev/erik/acl/acl")
```

Then keep the same dependency declaration:
```kotlin
implementation("io.liquidsoftware:acl:0.3.0-SNAPSHOT")
```

## Maven Central

This project is wired for Central Portal publishing through the same Gradle + `com.gradleup.nmcp` setup used in the `workflow` project.

For a release publish you will need:

- a Central Portal account
- a registered `io.liquidsoftware` namespace
- a GPG key for signing artifacts
- Central Portal credentials and signing keys in Gradle properties or environment variables

Typical Gradle properties:

```properties
centralPortalUsername=...
centralPortalPassword=...
signing.keyId=...
signing.password=...
signing.secretKeyRingFile=...
```

To publish a release to Sonatype / Maven Central:

```bash
./gradlew publishAllPublicationsToCentralPortal
```

Before publishing, make sure:

- `version = "x.y.z"` in [build.gradle.kts](build.gradle.kts)
- `CHANGELOG.md` includes the release notes
- `centralPortalUsername` and `centralPortalPassword` are configured in `~/.gradle/gradle.properties`
- your signing key is configured via `signing.keyId`, `signing.password`, and `signing.secretKeyRingFile`

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

val decision = acl.decide(bob, Read, Book(userId = "alice"))
decision.granted            // false
(decision as AccessDecision.Denied).reason.message  // "No matching allow rule"
```

The catalog is typed on the subject, so `acl.canRead("bob", book)` does not compile.

Policies can also be built on their own with `aclPolicy<User, Book> { ... }` and added with `register(policy)`, which is useful when policies live next to the resources they protect.

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

## Contract

The stable behavior is covered by tests and includes:

- resources route to the policy for their most specific registered supertype
- subjects may be any subtype of the policy's subject type, including sealed hierarchies
- ambiguous routing (two unrelated matching supertypes) fails fast
- duplicate registration rejection
- the catalog's subject type is checked at compile time
- one `allow` rule can grant several operations
- `Manage` implies `Read` and `Write`
- `Read` and `Write` do not imply each other
- empty policies deny all access
- empty catalogs deny unknown resources
- denied decisions carry a structured reason with a human-readable message

## Project Shape

This repository currently uses a single Gradle module for the core ACL engine.
The earlier Maven submodules and framework-specific adapters were removed during the reset.

If we bring Spring Boot back later, the cleanest path is likely to reintroduce it as a separate Gradle module so the core stays framework-neutral.

## Limitations

Current caveats and future improvement ideas are tracked in [docs/limitations-and-future-work.md](docs/limitations-and-future-work.md).
