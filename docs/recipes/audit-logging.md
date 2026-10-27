# Audit logging

> Compiled: every example here is run by
> [`AuditLoggingRecipeTest`](../../src/test/kotlin/io/liquidsoftware/acl/recipes/audit/AuditLoggingRecipeTest.kt).

Security reviews ask "who tried to do what, and were they allowed?". Every decision
already carries the answer, so recording it is a thin wrapper around `decide`.

## A recording wrapper

```kotlin
data class AuditEntry(val subjectId: String, val operation: Operation, val resource: String, val decision: AccessDecision)

class AuditedAcl<S : Any>(
    private val acl: AclCatalog<S>,
    private val subjectId: (S) -> String,
    private val resourceId: (Any) -> String,
    private val record: (AuditEntry) -> Unit,
) {
    fun decide(subject: S, operation: Operation, resource: Any): AccessDecision =
        acl.decide(subject, operation, resource).also { decision ->
            record(AuditEntry(subjectId(subject), operation, resourceId(resource), decision))
        }

    fun can(subject: S, operation: Operation, resource: Any): Boolean = decide(subject, operation, resource).granted
}
```

The entry holds ids, not the subject and resource themselves: a `toString()` of a user
or a document is a fine way to put personal data in your logs.

```kotlin
val log = mutableListOf<AuditEntry>()
val audited = AuditedAcl(
    acl,
    subjectId = User::id,
    resourceId = { resource -> if (resource is Note) "note:${resource.id}" else resource::class.simpleName.orEmpty() },
    record = log::add,
)

val note = Note("n1", ownerId = "alice")
audited.can(User("alice"), Write, note)  // true, recorded
audited.can(User("bob"), Write, note)    // false, recorded with reason "No rule allows Write on com.example.Note"
```

In production `record` writes to your logger or audit table; in tests it's a list, as
here.

## Audit actions, not list filtering

Use the audited wrapper where a user acts (open, edit, approve, delete), and the plain
catalog for filtering lists and deciding which buttons to show. A list screen of 50 rows
asks 50 or more questions nobody needs a record of, and burying the one denied `Write` in
them defeats the point.

## Denials worth an alert

`reason` tells a user error from a bug:

- `NoMatchingAllowRule`: the user asked for something they may not do. Normal; log it at
  info, and alert only on unusual volume.
- `NoPolicyRegistered` or `AmbiguousPolicy`: the catalog is wired wrong for that resource
  type. That's a bug, so log it as an error. A test with `hasPolicyFor` (see the
  [tutorial](../tutorial.md#13-testing-your-catalog)) keeps it out of production.
