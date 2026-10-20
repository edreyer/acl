# Limitations and Future Work

Known limitations of the current design, and ideas for addressing them. Nothing here is a commitment.

## Current limitations

### Ambiguous routing is detected on first use

Resources route to the policy for their most specific registered type. If a resource matches two registered types and neither is a subtype of the other, the check is denied with `AmbiguousPolicy`. Because the catalog cannot know every runtime type up front, this is found on the first check for that type, not when the catalog is built. Through the boolean `can*` checks it looks like an ordinary denial.

### Exceptions from rules propagate

Checks never throw for denial, but a rule is your code, and an exception it throws propagates out of `can`/`decide`. The library does not catch it, because turning it into a denial would hide bugs. Keep rules to plain reads of data you already have.

### Allow-only rules

There is no `deny(...)`. Adding one requires clear precedence rules, so it should wait until a real use case needs it.

### No framework integrations

There are no Arrow, Spring Security or Ktor adapters today. If they return, each should be a separate module that depends on the core (see `AGENTS.md`).
