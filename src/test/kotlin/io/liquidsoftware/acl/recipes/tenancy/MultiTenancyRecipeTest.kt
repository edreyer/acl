package io.liquidsoftware.acl.recipes.tenancy

import io.liquidsoftware.acl.Operation.Manage
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import io.liquidsoftware.acl.aclCatalog
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// Mirrors docs/recipes/multi-tenancy.md. If you change an example there, change it here too.

private interface TenantOwned {
    val tenantId: String
}

private data class User(val id: String, val tenantId: String, val isTenantAdmin: Boolean = false)

private data class Project(override val tenantId: String, val ownerId: String) : TenantOwned
private data class Report(override val tenantId: String, val authorId: String, val isPublished: Boolean) : TenantOwned

private fun User.inTenantOf(resource: TenantOwned) = tenantId == resource.tenantId

private val acl = aclCatalog<User> {
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

class MultiTenancyRecipeTest {
    private val ann = User("ann", tenantId = "acme")
    private val acmeAdmin = User("root", tenantId = "acme", isTenantAdmin = true)
    private val globexAdmin = User("root", tenantId = "globex", isTenantAdmin = true)
    private val project = Project(tenantId = "acme", ownerId = "ann")

    @Test
    fun the_tenant_check_is_part_of_every_rule() {
        assertTrue(acl.canWrite(ann, project))
        assertTrue(acl.canManage(acmeAdmin, project))
        assertFalse(acl.canRead(globexAdmin, project))
        assertFalse(acl.canRead(User("ann", tenantId = "globex"), project))
    }

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

    @Test
    fun a_supertype_policy_does_not_stack_on_a_subtype_policy() {
        val stacked = aclCatalog<User> {
            policy<TenantOwned> {
                allow(Manage) { user, resource -> user.inTenantOf(resource) && user.isTenantAdmin }
            }
            policy<Project> {
                allow(Read) { user, project -> user.id == project.ownerId }
            }
        }
        // Project routes to its own policy only, so the tenant check above never runs for it.
        assertTrue(stacked.canRead(User("ann", tenantId = "globex"), project))
        assertFalse(stacked.canManage(acmeAdmin, project))
    }
}
