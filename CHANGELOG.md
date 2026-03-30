# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, with a simple `Unreleased` section during active development.

## [Unreleased]

### Added

- Added a domain-facing `Authorizer<S, R>` API to `acl-core`.
- Added the `authorizer { ... }` DSL and `RuleScope<S, R>` for expressing authorization rules directly in domain terms.
- Added authorizer-first Arrow helpers in `acl-arrow`, including `ensureHasAccess`, `ensureCanRead`, `ensureCanWrite`, and `ensureCanManage`.
- Added `DenialContext` so access denials can carry structured context without splitting the error type.

### Changed

- Reworked the README to lead with the authorizer-first API and move the lower-level ACL engine to an advanced section.

### Breaking Changes

- `AuthorizationError` now uses a single denial type: `AccessDenied`.
- The old `PermissionDenied` subtype has been removed.
- Low-level ACL failures now attach `DenialContext.Acl(resourceId, subjectId)` to `AccessDenied`.
- Generic authorizer failures now use `AccessDenied(permission, DenialContext.Unknown)`.
- Code that previously matched on `PermissionDenied` must now inspect `AccessDenied.context`.
