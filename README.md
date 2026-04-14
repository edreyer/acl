# ACL

`acl` is a small Kotlin ACL library for answering one question well:

Can subject `A` access resource `B`?

The library is intentionally small:

- pure ACL core
- allow-only rules
- `Manage` implies `Read` and `Write`
- exact-match resource routing
- collection helpers for batch checks and filtering

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
signingInMemoryKey=...
signingInMemoryKeyPassword=...
```

To publish a release to Sonatype / Maven Central:

```bash
./gradlew publishAllPublicationsToCentralPortal
```

Before publishing, make sure:

- `version = "x.y.z"` in [build.gradle.kts](build.gradle.kts)
- `CHANGELOG.md` includes the release notes
- `centralPortalUsername` and `centralPortalPassword` are configured in `~/.gradle/gradle.properties`
- your signing key is configured via `signingInMemoryKey` and `signingInMemoryKeyPassword`, or the equivalent GPG file-based properties

## Quick Start

```kotlin
import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.catalog.aclCatalog
import io.liquidsoftware.acl.policy.aclPolicy

data class User(val id: String, val isSystemAdmin: Boolean)
data class Book(val userId: String)

val bookPolicy = aclPolicy<User, Book> {
    allow(Operation.Manage) { user -> user.isSystemAdmin }
    allow(Operation.Read) { user, book -> user.id == book.userId }
    allow(Operation.Write) { user, book -> user.id == book.userId }
}

val catalog = aclCatalog {
    register(bookPolicy)
}

val bob = User(id = "bob", isSystemAdmin = false)
val admin = User(id = "root", isSystemAdmin = true)
val book = Book(userId = "bob")

catalog.canRead(bob, book)
catalog.canWrite(bob, book)
catalog.canManage(admin, book)

val decision = catalog.decide(bob, Operation.Read, Book(userId = "alice"))
decision.granted
decision.reason.message
```

## Collection Helpers

```kotlin
catalog.canReadAll(bob, books)
catalog.canWriteAll(bob, books)
catalog.canManageAll(bob, books)
catalog.filterReadableBy(bob, books)
catalog.filterWritableBy(bob, books)
catalog.filterManageableBy(bob, books)
catalog.partitionReadableBy(bob, books)
catalog.partitionWritableBy(bob, books)
catalog.partitionManageableBy(bob, books)
catalog.decideAll(bob, Operation.Read, books)
```

## Contract

The stable behavior is covered by tests and includes:

- exact-match resource routing
- duplicate registration rejection
- fail-fast validation for wrong subject type
- `Manage` implies `Read` and `Write`
- `Read` and `Write` do not imply each other
- empty collections are granted by `can*All(...)`
- empty policies deny all access
- empty catalogs deny unknown resources
- denied decisions carry a structured reason with a human-readable message

## Project Shape

This repository currently uses a single Gradle module for the core ACL engine.
The earlier Maven submodules and framework-specific adapters were removed during the reset.

If we bring Spring Boot back later, the cleanest path is likely to reintroduce it as a separate Gradle module so the core stays framework-neutral.

## Limitations

Current caveats and future improvement ideas are tracked in [docs/limitations-and-future-work.md](docs/limitations-and-future-work.md).
