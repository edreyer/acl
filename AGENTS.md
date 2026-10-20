# AGENTS.md

Guidance for AI agents (and humans) working on this repository.

## Project Goal

`acl` is a small, framework-neutral Kotlin library that answers: can subject `A` perform operation `X` on resource `B`?

It should stay small, generic, and easy to understand for users who were not involved in building it. Optimize for readable call sites and a small public surface.

## Current Shape

- One Gradle module, one package: `io.liquidsoftware.acl`.
- Builds with JDK 21 but targets JDK 17 (bytecode, JDK APIs and Gradle metadata). `testMinimumJdk` runs the tests on 17.
- Kotlin explicit API mode is on; every public symbol is a deliberate choice.
- Every public class and function has KDoc (detekt's `UndocumentedPublicClass`/`UndocumentedPublicFunction` enforce it), since the Dokka output is published.
- Public API:
  - `aclCatalog<S> { policy<R> { ... }; register(policy) }` returns `AclCatalog<S>`
  - `AclCatalog<S>`: `decide`, `can`, `canRead`, `canWrite`, `canManage`, `forSubject`, `hasPolicyFor`
  - `SubjectAccess<S>`: the same checks with the subject bound
  - `aclPolicy<S, R> { allow(op, ...) { ... } }` returns `AclPolicy<S, R>`
  - `Operation`: an open interface with built-in `Read`, `Write` and `Manage` (which covers `Read` and `Write`, never custom operations); users declare their own as objects
  - `AccessDecision` (`Granted`, `Denied`), `DenialReason` (`NoMatchingAllowRule`, `NoPolicyRegistered`, `AmbiguousPolicy`)
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

Exceptions are only for programmer or configuration errors caught while building the catalog, such as registering two policies for one type or a `policy<Any>`. The library never throws at check time: problems it finds then, such as ambiguous routing, are denials. Exceptions thrown by callers' rules propagate unchanged; don't catch them, since that would hide bugs.

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
- `ReadmeExamplesTest` mirrors the README examples and `MigrationGuideExamplesTest` mirrors the 0.5 code in `docs/migrating-to-0.5.md`. If you change an example in either doc, update its test in the same change.
- `api/acl.api` is the checked-in public API. `./gradlew check` fails when the public API changes without it; run `./gradlew updateKotlinAbi` and commit the diff when the change is intended.
- Run `./gradlew check` (tests, detekt, API check) before pushing; CI runs the same.

## Documentation

- Keep `README.md` focused on users: install, quick start, rules, collections, type hierarchies, behavior.
- Release mechanics live in `RELEASING.md`.
- Record user-visible changes in `CHANGELOG.md` under `Unreleased`, with a `Breaking Changes` section when callers must change code.
- Known limitations and ideas live in `docs/limitations-and-future-work.md`.

## When Extending the Library

1. Ask whether the concept is framework-neutral and useful to most users. If not, it belongs in the caller's code or an integration module.
2. Prefer extending existing types over adding new entry points.
3. When in doubt, choose the smaller public surface.
