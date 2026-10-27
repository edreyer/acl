# Permission matrix tests

> Compiled: every example here is run by
> [`PermissionMatrixRecipeTest`](../../src/test/kotlin/io/liquidsoftware/acl/recipes/matrix/PermissionMatrixRecipeTest.kt).

One test per rule works while a policy is small. Past a handful of rules, a table of
"who may do what to which resource" is easier to review, and it can list what each
subject must **not** do as well as what they may.

## The policy under test

```kotlin
data class User(val id: String, val isAdmin: Boolean = false)
data class Document(val ownerId: String, val isPublic: Boolean = false)
data object Publish : Operation

val acl = aclCatalog<User> {
    policy<Document> {
        allow(Manage) { user -> user.isAdmin }
        allow(Read, Write) { user, doc -> user.id == doc.ownerId }
        allow(Publish) { user, doc -> user.id == doc.ownerId && !doc.isPublic }
        allow(Read) { _, doc -> doc.isPublic }
    }
}
```

## The matrix

Each row names a subject, a resource and the operations it allows. Every operation not
named is expected to be denied, so a rule that grants too much fails the test as surely
as one that grants too little:

```kotlin
val operations = listOf(Read, Write, Manage, Publish)

fun expect(subject: User, resource: Any, vararg allowed: Operation) =
    operations.map { operation -> Triple(subject, operation, resource) to (operation in allowed) }

val matrix = listOf(
    expect(owner, draft, Read, Write, Publish),
    expect(owner, published, Read, Write),
    expect(stranger, draft),
    expect(stranger, published, Read),
    expect(admin, draft, Read, Write, Manage),
    expect(admin, published, Read, Write, Manage),
).flatten()
```

The admin rows are the ones worth a second look in review: `Manage` covers `Read` and
`Write` but not `Publish`, so admins can't publish other people's documents.

## One test, every failure

Check the whole table and report every wrong cell at once, not just the first:

```kotlin
@Test
fun permission_matrix() {
    val wrong = matrix.filter { (case, expected) ->
        val (subject, operation, resource) = case
        acl.can(subject, operation, resource) != expected
    }
    val report = wrong.joinToString("\n") { (case, expected) -> "$case should be ${if (expected) "allowed" else "denied"}" }
    assertTrue(wrong.isEmpty(), report)
}
```

If you use JUnit 5's `@ParameterizedTest` or Kotest's `withData`, feed them the same
`matrix` to get one reported test per cell instead.

When you add an operation, add it to `operations`: every row then expects it denied until
you say otherwise, which is the same default the catalog has.
