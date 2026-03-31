# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, with a simple `Unreleased` section during active development.

## [Unreleased]

## [0.3.0] - 2026-04-01

### Added

- Added `DenialContext.Metadata` and optional denial-context builders to authorizer Arrow helpers so denials can carry structured metadata.
- Spring Security Arrow authorizer helpers now forward optional denial-context metadata instead of discarding it.

### Changed

- Spring Security integration types are now plain Kotlin classes wired explicitly through constructors instead of component discovery.
- Spring Security now separates subject resolution from authorization: `SpringSecurityAccessSubjectProvider` only resolves the current subject, while `SpringSecurityAclChecker` owns ACL and authorizer checks.
- Core ACL permission checks are synchronous because they only inspect in-memory ACL data; the Spring and Ktor low-level ACL wrappers follow the same model, while the coroutine boundary stays on authorizer rule evaluation.

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
