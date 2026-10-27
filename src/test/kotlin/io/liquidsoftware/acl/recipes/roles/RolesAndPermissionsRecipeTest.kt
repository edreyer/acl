package io.liquidsoftware.acl.recipes.roles

import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import io.liquidsoftware.acl.aclCatalog
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// Mirrors docs/recipes/roles-and-permissions.md. If you change an example there, change it here too.

private enum class Permission { ViewAllInvoices, ApproveInvoices, ExportInvoices }

private data class User(val id: String, val permissions: Set<Permission>) {
    fun has(permission: Permission) = permission in permissions
}

private data class Invoice(val id: String, val ownerId: String)

private data object Approve : Operation
private data object Export : Operation

private val acl = aclCatalog<User> {
    policy<Invoice> {
        allow(Read) { user -> user.has(Permission.ViewAllInvoices) }
        allow(Read, Write) { user, invoice -> user.id == invoice.ownerId }
        allow(Approve) { user, invoice -> user.has(Permission.ApproveInvoices) && user.id != invoice.ownerId }
        allow(Export) { user -> user.has(Permission.ExportInvoices) }
    }
}

private enum class Role(val permissions: Set<Permission>) {
    Clerk(emptySet()),
    Accountant(setOf(Permission.ViewAllInvoices, Permission.ApproveInvoices)),
    Auditor(setOf(Permission.ViewAllInvoices, Permission.ExportInvoices)),
}

private fun userWithRoles(id: String, roles: Set<Role>): User =
    User(id, roles.flatMapTo(mutableSetOf()) { it.permissions })

class RolesAndPermissionsRecipeTest {
    private val clara = userWithRoles("clara", setOf(Role.Clerk))
    private val ann = userWithRoles("ann", setOf(Role.Accountant))
    private val olga = userWithRoles("olga", setOf(Role.Auditor))
    private val invoice = Invoice("inv-1", ownerId = "clara")

    @Test
    fun rules_read_permissions() {
        assertTrue(acl.canRead(clara, invoice))
        assertTrue(acl.canRead(olga, invoice))
        assertFalse(acl.canWrite(olga, invoice))
        assertTrue(acl.can(ann, Approve, invoice))
        assertFalse(acl.can(clara, Approve, invoice))
        assertFalse(acl.can(ann, Approve, Invoice("inv-2", ownerId = "ann")))
        assertTrue(acl.can(olga, Export, invoice))
    }

    @Test
    fun tests_build_users_from_permissions() {
        val approver = User("ann", setOf(Permission.ApproveInvoices))
        assertTrue(acl.can(approver, Approve, invoice))
    }
}
