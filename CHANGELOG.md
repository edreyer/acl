# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, with a simple `Unreleased` section during active development.

## [Unreleased]

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
