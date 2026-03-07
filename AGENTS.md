# AGENTS.md

This document provides project-specific guidance for AI agents working on the standalone ACL project that will be extracted from this repository.

## Project Goal

This project is a small OSS ACL library for Kotlin applications.

Its job is to provide:

- a pure ACL core
- an optional Arrow integration
- an optional Spring Security integration
- an optional Spring Security + Arrow bridge

The library must remain generic, reusable, and easy to understand. It is not an application module and must not accumulate app-specific concepts from the source repository.

## Architectural Rules

### Module boundaries are strict

Preserve these dependency rules:

- `acl-core`
  - pure Kotlin
  - no Spring
  - no Arrow
- `acl-arrow`
  - may depend on `acl-core`
  - must not depend on Spring
- `acl-spring-security`
  - may depend on `acl-core`
  - must not depend on Arrow
- `acl-spring-security-arrow`
  - may depend on `acl-core`
  - may depend on `acl-arrow`
  - may depend on `acl-spring-security`

Do not collapse these modules for convenience.

### Keep the core generic

Do not introduce or retain application-specific concepts such as:

- `ExecutionContext`
- `WorkflowError`
- `UnauthorizedWorkflowError`
- `UserDetailsWithId`
- bounded-context names like `booking`, `payment`, `user`
- Mongo persistence concerns
- controller or HTTP response concepts

`acl-core` should expose generic authorization types only.

### Expected denial is data

Permission denial is an expected outcome.

Prefer:

- `Boolean` in the pure core
- typed authorization errors
- `Raise` and `Either` in Arrow integration layers

Do not use exceptions as the default mechanism for normal authorization denial.

### Current-subject behavior is adapter logic

The core library must not know how to resolve the current subject.

That belongs in integration modules such as:

- Spring Security adapters
- future Ktor adapters

## Kotlin Design Guidance

- Prefer small, explicit public APIs.
- Prefer data classes, enums, and sealed interfaces where they clarify the model.
- Use Kotlin idioms, but avoid clever syntax that obscures meaning.
- Keep the DSL useful and restrained.
- Prefer names that read well in real application code.

Examples:

- `acl(resourceId) { manager(userId) }`
- `checker.hasPermission(acl, subject, Permission.READ)`
- `checker.ensureCanRead(subject, acl)`

Avoid over-designed DSL syntax that reads well in demos but poorly in maintenance.

## OSS Guidance

Optimize for library users who were not involved in building it.

That means:

- package names must be generic and stable
- artifact names must reflect clear module responsibilities
- examples in docs must compile and reflect real APIs
- public APIs should be intentionally curated
- avoid exposing internal convenience APIs unless they add durable value

When in doubt, prefer the smaller public surface.

## Testing Expectations

Every public behavior added to a module should have direct tests in that module.

Minimum expectations:

- `acl-core`
  - ACL evaluation tests
  - builder DSL tests
- `acl-arrow`
  - `Raise` enforcement tests
  - `SecuredResource` overload tests
- `acl-spring-security`
  - current-subject resolution tests
  - boolean permission checks using resolved subject
- `acl-spring-security-arrow`
  - current-subject `Raise` enforcement tests

If documentation examples are changed materially, add or update tests so those examples remain trustworthy.

## Migration Constraints

The new project will be created by extracting code from an application repository.

Agents working in the new repo should:

- remove app branding and app-local package names as needed
- preserve the module split
- remove any dependencies that only existed because of the source app
- avoid reintroducing cross-module coupling
- keep the new project ready to be consumed back by the source app as a dependency

## Things To Avoid

- Do not move Arrow into `acl-core`.
- Do not move Spring Security into `acl-core`.
- Do not make Spring users depend on Arrow.
- Do not make Arrow users depend on Spring.
- Do not add application workflow or HTTP abstractions to the library.
- Do not reintroduce exception-driven ACL checks as the primary API.

## Preferred Evolution Path

When extending the library, prefer this order:

1. improve `acl-core` if the concept is framework-neutral
2. add Arrow ergonomics in `acl-arrow` if needed
3. add framework adapters in dedicated modules
4. add bridge modules only when two optional ecosystems need to work together

This keeps the project modular and extraction-friendly.
