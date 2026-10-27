# Roles and permissions

> Compiled: every example here is run by
> [`RolesAndPermissionsRecipeTest`](../../src/test/kotlin/io/liquidsoftware/acl/recipes/roles/RolesAndPermissionsRecipeTest.kt).

The library has no idea of a role, by design. Your app probably does: roles stored in a
database, granted by an admin screen. Keep that machinery where it is, and hand the
catalog a subject that already knows what it may do.

## Put permissions on the subject

Resolve roles to a set of permissions when you load the user (at login, or per request),
and let rules read the permissions:

```kotlin
enum class Permission { ViewAllInvoices, ApproveInvoices, ExportInvoices }

data class User(val id: String, val permissions: Set<Permission>) {
    fun has(permission: Permission) = permission in permissions
}

data class Invoice(val id: String, val ownerId: String)

data object Approve : Operation
data object Export : Operation

val acl = aclCatalog<User> {
    policy<Invoice> {
        allow(Read) { user -> user.has(Permission.ViewAllInvoices) }
        allow(Read, Write) { user, invoice -> user.id == invoice.ownerId }
        allow(Approve) { user, invoice -> user.has(Permission.ApproveInvoices) && user.id != invoice.ownerId }
        allow(Export) { user -> user.has(Permission.ExportInvoices) }
    }
}
```

A permission says what a user may do; a rule says when. "Accountants approve invoices"
is a permission, "but never their own" is the rule.

## Map roles to permissions in one place

```kotlin
enum class Role(val permissions: Set<Permission>) {
    Clerk(emptySet()),
    Accountant(setOf(Permission.ViewAllInvoices, Permission.ApproveInvoices)),
    Auditor(setOf(Permission.ViewAllInvoices, Permission.ExportInvoices)),
}

fun userWithRoles(id: String, roles: Set<Role>): User =
    User(id, roles.flatMapTo(mutableSetOf()) { it.permissions })
```

If roles live in a database table instead of an enum, the shape is the same: one query
turns the user's roles into a `Set<Permission>` before the first check.

```kotlin
val clara = userWithRoles("clara", setOf(Role.Clerk))
val ann = userWithRoles("ann", setOf(Role.Accountant))
val olga = userWithRoles("olga", setOf(Role.Auditor))
val invoice = Invoice("inv-1", ownerId = "clara")

acl.canRead(clara, invoice)                              // true, she owns it
acl.canRead(olga, invoice)                               // true, ViewAllInvoices
acl.canWrite(olga, invoice)                              // false, auditors only look
acl.can(ann, Approve, invoice)                           // true
acl.can(clara, Approve, invoice)                         // false, clerks can't approve
acl.can(ann, Approve, Invoice("inv-2", ownerId = "ann")) // false, nobody approves their own invoice
acl.can(olga, Export, invoice)                           // true
```

## Why not check roles in the rules?

`allow(Approve) { it.role == Role.Accountant }` works, but it ties every policy to today's
org chart. With permissions in between:

- adding a role, or giving an existing one more power, changes the `Role` table and no policy
- tests build exactly the user they mean, without knowing which role grants what:

```kotlin
val approver = User("ann", setOf(Permission.ApproveInvoices))
acl.can(approver, Approve, invoice)  // true
```

Keep `Permission` coarse ("may approve invoices"), and leave the fine print (whose
invoice, what state it is in) to the rules, where it can see the resource.
