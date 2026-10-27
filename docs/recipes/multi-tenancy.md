# Multi-tenancy

> Compiled: every example here is run by
> [`MultiTenancyRecipeTest`](../../src/test/kotlin/io/liquidsoftware/acl/recipes/tenancy/MultiTenancyRecipeTest.kt).

In a multi-tenant app the first question is always "same tenant?", and only then "may
this user do this?". The library has no tenant concept, so the tenant check is one more
predicate, and the job is to make it impossible to forget.

## Give resources a tenant, and write the check once

```kotlin
interface TenantOwned {
    val tenantId: String
}

data class User(val id: String, val tenantId: String, val isTenantAdmin: Boolean = false)

data class Project(override val tenantId: String, val ownerId: String) : TenantOwned
data class Report(override val tenantId: String, val authorId: String, val isPublished: Boolean) : TenantOwned

fun User.inTenantOf(resource: TenantOwned) = tenantId == resource.tenantId
```

## Start every rule with it

```kotlin
val acl = aclCatalog<User> {
    policy<Project> {
        allow(Manage) { user, project -> user.inTenantOf(project) && user.isTenantAdmin }
        allow(Read, Write) { user, project -> user.inTenantOf(project) && user.id == project.ownerId }
    }
    policy<Report> {
        allow(Manage) { user, report -> user.inTenantOf(report) && user.isTenantAdmin }
        allow(Read, Write) { user, report -> user.inTenantOf(report) && user.id == report.authorId }
        allow(Read) { user, report -> user.inTenantOf(report) && report.isPublished }
    }
}

val ann = User("ann", tenantId = "acme")
val acmeAdmin = User("root", tenantId = "acme", isTenantAdmin = true)
val globexAdmin = User("root", tenantId = "globex", isTenantAdmin = true)
val project = Project(tenantId = "acme", ownerId = "ann")

acl.canWrite(ann, project)                             // true
acl.canManage(acmeAdmin, project)                      // true
acl.canRead(globexAdmin, project)                      // false, admin of another tenant
acl.canRead(User("ann", tenantId = "globex"), project) // false, same id, other tenant
```

Rules only ever allow, so a rule that leaves out `inTenantOf` is the one way to leak
across tenants. Make that a test failure rather than a code-review catch:

```kotlin
@Test
fun nobody_crosses_tenants() {
    val outsider = User("ann", tenantId = "globex", isTenantAdmin = true)
    val samples = listOf(
        Project(tenantId = "acme", ownerId = "ann"),
        Report(tenantId = "acme", authorId = "ann", isPublished = true),
    )
    for (resource in samples) {
        for (operation in listOf(Read, Write, Manage)) {
            assertFalse(acl.can(outsider, operation, resource), "$operation on $resource")
        }
    }
}
```

The outsider shares an id with a real owner and is an admin, so the only thing that can
deny them is the tenant check. Add a sample, and any custom operations, whenever you add
a policy.

## Why not a `policy<TenantOwned>`?

It looks like a place to put the tenant check once, but policies don't stack. A resource
is routed to the policy for its most specific registered type, so a `Project` uses the
`Project` policy alone and the `TenantOwned` rules never run for it:

```kotlin
val stacked = aclCatalog<User> {
    policy<TenantOwned> {
        allow(Manage) { user, resource -> user.inTenantOf(resource) && user.isTenantAdmin }
    }
    policy<Project> {
        allow(Read) { user, project -> user.id == project.ownerId }
    }
}

stacked.canRead(User("ann", tenantId = "globex"), project)  // true: no tenant check ran
stacked.canManage(acmeAdmin, project)                       // false: the TenantOwned rule never ran either
```

## Filter by tenant in queries too

The catalog is the authority, but don't make it the only line of defense. Scope every
query to the caller's tenant (a `WHERE tenant_id = ?`, a Hibernate filter, row-level
security), so a list screen never even loads another tenant's rows. The catalog then
checks what the query returned; see [Lists and queries](lists-and-queries.md).
