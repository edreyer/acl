# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, with a simple `Unreleased` section during active development.

## [Unreleased]

### Changed

- `AmbiguousPolicy.candidates` (and its message) now lists only the conflicting types, not every matching supertype.
- The per-class routing cache no longer keeps resource classes or their classloaders reachable, which matters for apps that reload classes.

## [0.4.0] - 2026-10-12

### Added

- `aclCatalog<S> { ... }` returns an `AclCatalog<S>`, so passing the wrong subject type is a compile error.
- `AclCatalog.forSubject(subject)` returns a `SubjectAccess<S>` whose `canRead`/`canWrite`/`canManage`/`can`/`decide` compose with Kotlin collection functions, for example `books.filter(access::canRead)`.
- `allow(...)` accepts several operations, for example `allow(Read, Write) { user, book -> ... }`.
- The build now uses Kotlin explicit API mode.
- Applications can declare their own operations (`data object Approve : Operation`). A custom operation is granted only by rules that name it (`Manage` does not cover it), and an operation can grant others by overriding `covers`.

### Changed

- Rewrote `AGENTS.md`, the README and the docs for the single-module, single-package API. Publishing instructions now live only in `RELEASING.md`.

### Fixed

- `./gradlew publishToMavenLocal` no longer requires a GPG key; artifacts are only required to be signed when publishing to Maven Central.
- Subjects that are subtypes of a policy's subject type (for example, members of a sealed hierarchy) are now accepted instead of failing with `IllegalArgumentException`.
- Resources whose runtime type is a subtype of a registered resource type (subclasses, interface implementations, ORM proxies) now route to the most specific matching policy instead of being denied with `NoPolicyRegistered`.
- A resource that matches two unrelated registered types is denied with the new `AmbiguousPolicy` reason, which names the types, instead of throwing during the check.
- Registering a policy for `Any` is rejected when the catalog is built, since with subtype routing it would replace default deny for every unregistered type.

### Breaking Changes

See [the migration guide](docs/migrating-to-0.4.md) for step-by-step upgrade instructions.

- All public types moved to the single package `io.liquidsoftware.acl`. The `catalog`, `decision` and `policy` subpackages are gone.
- `aclCatalog { policy<User, Book> { ... } }` is now `aclCatalog<User> { policy<Book> { ... } }`.
- `AclCatalog` methods take `resource: Any` and a subject of the catalog's type instead of free type parameters. The runtime "Expected subject of type" check is gone because the compiler enforces it.
- Removed the collection helpers `canAll`, `canReadAll`, `canWriteAll`, `canManageAll`, `filterBy`, `filterReadableBy`, `filterWritableBy`, `filterManageableBy`, `partitionBy`, `partitionReadableBy`, `partitionWritableBy`, `partitionManageableBy` and `decideAll`, along with `BatchAccessDecision`, `ItemAccessDecision` and `AccessPartition`. Use `forSubject` with `filter`, `partition`, `all` or `associateWith`.
- `AclRule` is no longer public, and `AclPolicy.resourceType` is internal.
- `Operation` is now an interface instead of an enum. `Operation.Read`, `Operation.Write` and `Operation.Manage` keep their names, but `Operation.entries`, `values()`, `valueOf()` and exhaustive `when` over operations are gone.

## [0.3.0] - 2026-04-14

### Added

- Added a new single-module Gradle build as part of the project reset.
- Added the `io.liquidsoftware.acl` package namespace for the reset ACL core.

### Changed

- Reset the project from the previous framework-heavy Maven multi-module layout to a single Gradle ACL core.
- Replaced the previous `io.liquidsoftware.common.security.*` implementation with the `acl2` core model under `io.liquidsoftware.acl.*`.
- Updated the README and project docs to match the new core-first library shape.

### Breaking Changes

- This is a full project reset, not a compatible evolution of the previous codebase.
- Removed the old Maven `acl-*` modules and root `pom.xml`.
- Renamed the public package namespace from `io.liquidsoftware.common.security.*` to `io.liquidsoftware.acl.*`.
- Removed the Ktor and Spring Security adapter modules during the reset.

## [0.2.0] - 2026-03-30

### Added

- Added a domain-facing `Authorizer<S, R>` API to `acl-core`.
- Added the `authorizer { ... }` DSL and `RuleScope<S, R>` for expressing authorization rules directly in domain terms.
- Added authorizer-first Arrow helpers in `acl-arrow`, including `ensureHasAccess`, `ensureCanRead`, `ensureCanWrite`, and `ensureCanManage`.
- Added `DenialContext` so access denials can carry structured context without splitting the error type.
- Added current-subject/current-call authorizer helpers to `acl-ktor`, `acl-spring-security`, and `acl-spring-security-arrow`.

### Changed

- Reworked the README to lead with the authorizer-first API and move the lower-level ACL engine to an advanced section.

### Breaking Changes

- `AuthorizationError` now uses a single denial type: `AccessDenied`.
- The old `PermissionDenied` subtype has been removed.
- Low-level ACL failures now attach `DenialContext.Acl(resourceId, subjectId)` to `AccessDenied`.
- Generic authorizer failures now use `AccessDenied(permission, DenialContext.Unknown)`.
- Code that previously matched on `PermissionDenied` must now inspect `AccessDenied.context`.
