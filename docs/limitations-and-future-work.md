# ACL Library Limitations and Future Work

This document captures the current weaknesses of the implementation and concrete ideas for improving it later.

## Current strengths

- simple public API
- clear allow-only rule model
- `Manage` implies lower operations
- catalog-based collection helpers
- modular policy definitions

## Current limitations

### 1. Resource routing is exact-match only

The catalog currently resolves policies by the exact runtime class of the resource.

Implications:

- sealed resource hierarchies are not handled automatically
- subclasses and proxy types may not resolve to the expected policy
- resource polymorphism is limited

When this is acceptable:

- each concrete resource type is its own policy boundary
- `Book` and `Invoice` each have distinct access rules
- the app prefers explicit, type-local policies over inheritance-based routing

When this is not acceptable:

- a subtype should inherit a parent policy
- ORM proxies should behave like the entity type they wrap
- a sealed hierarchy should share one policy family

### 2. Policy lookup still has one narrow unchecked cast boundary

The public API is generic and pleasant to use, and the catalog now stores typed policy bindings with subject/resource metadata. There is still one internal cast when the binding delegates into the typed policy.

Implications:

- the API is still not fully compile-time safe at the catalog boundary
- the runtime validation is better contained than before
- incorrect registration or type mismatches are still caught at runtime, not compile time

### 3. Denial reasons are structured, but still minimal

The current behavior is to return `Denied(Reason)` with a small denial-reason ADT for both policy-level denials and missing-policy catalog denials.

Implications:

- the behavior is predictable
- but the contract is not yet fully structured
- the reason model is intentionally small and not yet expressive enough for auditing or user-facing explanations

### 4. Batch decision metadata is minimal

The batch result currently carries per-item granted/denied state, but not richer auditing information.

Implications:

- useful for filtering and boolean checks
- still thin for debugging or audit-heavy applications

### 5. The DSL is functional but still generic

The policy DSL works, but it is still close to a low-level rule builder.

Implications:

- it is readable
- but it could be more domain-expressive and concise for common patterns

### 6. No explicit deny rules yet

The current model is allow-only.

Implications:

- this keeps v1 simple
- but some real systems need explicit deny and precedence rules

## Future improvement ideas

### Resource hierarchy-aware lookup

Add policy resolution that can consider:

- exact type
- supertypes
- interfaces
- most-specific match

This would make ADT-like resource hierarchies work more naturally.

### Strongly typed catalog registration

Improve registration so the catalog retains stronger type information and reduces reliance on casts.

Possible approaches:

- typed policy keys
- a richer policy descriptor
- a registry that stores the resource type and policy together in a typed wrapper

### Better decision reasons

Expand the denial-reason ADT with richer variants for auditing and user-facing explanations.

Possible shape:

- `MissingPolicy`
- `NoMatchingRule`
- `ExplicitlyDenied`
- `UnknownFailure`

### Explicit deny rules

Add `deny(...)` alongside `allow(...)` if the user needs it.

This would require defining precedence rules clearly.

### More expressive DSL sugar

Add convenience forms for common cases:

- owner-based rules
- global subject-only access
- rule naming
- policy naming

Example goal:

- make the common `User` / `Book` ownership rule read almost like business language

### Batch audit output

Extend batch results with:

- policy name
- rule match details
- denial reason per item

This would help when the catalog is used for audits or troubleshooting.

### Optional policy composition helpers

Add helpers for common assembly patterns:

- register multiple policies from a module
- create a catalog from a list of policies
- merge catalogs where appropriate

### Documentation and examples

Add a small set of executable examples showing:

- ownership checks
- system admin checks
- collection filtering
- batch decisions

This would make the API easier to learn and harder to misuse.

## Recommended next iteration

If we continue after v1, the most valuable improvements are probably:

1. resource hierarchy-aware policy lookup
2. structured denial reasons
3. more expressive DSL helpers

Those give the best balance of usability and safety without complicating the first release too much.
