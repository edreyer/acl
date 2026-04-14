# ACL Library Requirements

## Purpose

Create a small Kotlin library for access-control decisions between two domain entities.

The library should answer:

> Can entity `A` access entity `B`?

The intended shape is a reusable, domain-first ACL engine that is easy to understand, easy to test, and pleasant to use from Kotlin.

## Goals

- Provide a simple API for evaluating access control.
- Model ACL concepts explicitly and type-safely.
- Keep authorization logic functional and deterministic.
- Support a DSL or fluent style that reads naturally in Kotlin.
- Make the library easy to embed in application code without framework lock-in.

## Non-goals

- User authentication.
- Persistence.
- Distributed authorization.
- Role management as a standalone system unless needed to express ACL rules.
- Framework-specific integrations in the first iteration.

## Core domain concepts

The library should model the problem using explicit domain types.

Likely concepts include:
- `Subject` or `Actor`: the entity attempting access
- `Resource` or `Target`: the entity being accessed
- `Permission` or `Action`: what kind of access is being requested
- `Rule`: a rule that grants or denies access
- `Decision`: the result of evaluating access

These concepts should be modeled with Kotlin ADTs where appropriate, such as sealed interfaces or enums, instead of relying on loosely typed strings.

The library should not hardcode how subject attributes such as `systemAdmin` are represented. Those attributes should be supplied by the consumer through the subject type and/or rule predicates.

## Functional model

The core evaluation logic should be:

- pure
- deterministic
- side-effect free
- easy to compose

A good fit is a function that takes a request and a rule set and returns a decision.

Preferred direction:

- represent inputs as immutable values
- represent outcomes as an algebraic data type
- avoid throwing exceptions for expected deny cases

## API design requirements

The public API should be:

- small
- discoverable
- readable at the call site
- hard to misuse

Prefer Kotlin features such as:
- extension functions for fluent evaluation
- DSL builders for declaring rules
- value classes for strongly typed identifiers where useful
- sealed types for outcomes and conditions

Example quality target:

- a consumer should be able to declare rules in a compact DSL
- a consumer should be able to ask a yes/no question with a single evaluation call
- the API should make the access subject, target, and rule intent obvious

## Decision semantics

The library should define a clear decision model.

At minimum, it should distinguish:
- access granted
- access denied

Denied results carry a structured reason in v1.

Operation semantics:

- `Manage` is the highest privilege.
- `Manage` implies `Read`.
- `Manage` implies `Write`.
- `Read` and `Write` remain independent of each other.

If the implementation needs richer feedback, extend the reason ADT while keeping the basic API easy to use.

Current rule-combination semantics:

- allow-only rules
- default deny
- any matching allow grants access

There is no explicit deny precedence in v1.

## Rule model

Rules should be explicit and composable.

Candidate rule dimensions:
- subject identity
- resource identity
- action/permission
- ownership or relationship
- predicate-based conditions

The rule system should support at least one straightforward way to express:
- allow a specific subject to access a specific resource
- allow based on a relation or predicate
- allow a subject to access all resources of a given type via a global rule

Explicit deny rules are a future extension, not part of v1.

Global rules should be represented as subject-only predicates, not as special-case engine behavior. For example, a system admin rule should be expressed as "allow this subject to `Manage` all resources" through a rule that depends only on the subject.

## DSL requirements

If a DSL is introduced, it should:

- read naturally in Kotlin
- avoid surprising control flow
- stay shallow enough to understand quickly
- compile to plain domain objects

The DSL should be optional. Core functionality should remain usable without it.

## Error handling

Expected authorization outcomes should be represented as values, not exceptions.

Exceptions should be reserved for:
- programmer errors
- invalid configuration
- impossible states

If invalid rule definitions are allowed, the library should validate them eagerly and report clear errors.

## Testing requirements

The first implementation should be covered by tests for:

- granted access
- denied access
- rule precedence
- empty rule sets
- conflicting rules
- DSL parsing/building behavior, if applicable

Tests should document the intended semantics, not just the implementation.

## Proposed first iteration

The implemented library should include:

- a minimal domain model for operation, rules, decisions, policy, and catalog
- a pure evaluator at the policy level
- a catalog that resolves policies by resource type
- a DSL for declaring ACL policies
- unit tests for core behavior and edge cases

## Current direction

Use an allow-only, default-deny policy engine with:

- subject-only global rules for broad access like system admin
- subject-and-resource rules for ownership and relationship checks
- operation inheritance where `Manage` covers `Read` and `Write`
- consumer-defined subject attributes and predicates, with no hardcoded admin concept in the engine
- an application-facing authorization catalog that composes policies and offers collection-oriented helpers
- exact-match resource routing by runtime resource type
- fail-fast validation for subject type mismatches
- internal type metadata captured at policy registration time to reduce unsafe casts

This keeps the library small while still supporting the common ACL cases we care about first.

The catalog should be the primary ergonomic entry point for application code. In addition to single-entity checks, it may expose helpers for collection workflows such as:

- checking whether all entities in a collection are readable
- checking whether all entities in a collection are writable
- checking whether all entities in a collection are manageable
- filtering to only the entities a subject can access
- partitioning collections into allowed and denied items
- evaluating a batch of decisions in one call

The low-level policy model should remain small and generic; collection helpers belong on the catalog, not on the evaluator.
