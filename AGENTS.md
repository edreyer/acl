# AGENTS.md

Guidance for AI agents (and humans) working on this repository.

## Project Goal

`acl` is a small, framework-neutral Kotlin library that answers: can subject `A` perform operation `X` on resource `B`?

It should stay small, generic, and easy to understand for users who were not involved in building it. Optimize for readable call sites and a small public surface.

## Current Shape

- One Gradle module, one package: `io.liquidsoftware.acl`.
- Kotlin explicit API mode is on; every public symbol is a deliberate choice.
- Public API:
  - `aclCatalog<S> { policy<R> { ... }; register(policy) }` returns `AclCatalog<S>`
  - `AclCatalog<S>`: `decide`, `can`, `canRead`, `canWrite`, `canManage`, `forSubject`
  - `SubjectAccess<S>`: the same checks with the subject bound
  - `aclPolicy<S, R> { allow(op, ...) { ... } }` returns `AclPolicy<S, R>`
  - `Operation`: an open interface with built-in `Read`, `Write` and `Manage` (which covers every operation); users declare their own as objects
  - `AccessDecision` (`Granted`, `Denied`), `DenialReason` (`NoMatchingAllowRule`, `NoPolicyRegistered`)
- Internals: `AclRule`, `AclPolicyRegistry` (routes a resource to the policy for its most specific registered type and caches the result per class).

## Design Rules

### Keep the core generic

The library must not know about applications. Do not add:

- user, role, tenant or permission-storage concepts
- persistence, HTTP, controller or workflow abstractions
- framework dependencies (Spring, Ktor, Arrow, ...) in this module

Subjects, resources and their attributes are the caller's own types. Rules are plain predicates over them.

### Expected denial is data

A denied check returns `false` or `AccessDecision.Denied(reason)`. Do not use exceptions for normal denial.

Exceptions are only for programmer or configuration errors, such as registering two policies for one type or ambiguous routing.

### Let the compiler do the work

- The catalog is typed on its subject. Do not reintroduce untyped `<S : Any>` entry points or runtime subject-type checks.
- Prefer sealed types and data classes for results and reasons.
- Prefer one clear way to do something over several overloads.

### Prefer Kotlin's standard library over new helpers

Collection workflows go through `forSubject` plus `filter`, `partition`, `all` and `associateWith`. Do not add `filterXBy`/`canXAll`-style helpers back to the catalog.

### Keep the DSL restrained

The DSL should read like the rule it expresses: `allow(Read, Write) { user, book -> user.id == book.userId }`. Avoid syntax that reads well in a demo but is hard to maintain or debug.

## Framework Integrations

There are none in this repository today. If they come back (Arrow `Raise` helpers, Spring Security or Ktor current-subject adapters), add each as a separate Gradle module that depends on the core. The core must never depend on them, and integrations must not depend on each other unless one is explicitly a bridge between two.

Resolving the "current subject" is always adapter logic, never core logic.

## Testing Expectations

- Every public behavior has a direct test.
- `ReadmeExamplesTest` mirrors the README examples. If you change an example in `README.md`, update that test in the same change.
- Run `./gradlew test detekt` before pushing; CI runs the same.

## Documentation

- Keep `README.md` focused on users: install, quick start, rules, collections, type hierarchies, behavior.
- Release mechanics live in `RELEASING.md`.
- Record user-visible changes in `CHANGELOG.md` under `Unreleased`, with a `Breaking Changes` section when callers must change code.
- Known limitations and ideas live in `docs/limitations-and-future-work.md`.

## When Extending the Library

1. Ask whether the concept is framework-neutral and useful to most users. If not, it belongs in the caller's code or an integration module.
2. Prefer extending existing types over adding new entry points.
3. When in doubt, choose the smaller public surface.
