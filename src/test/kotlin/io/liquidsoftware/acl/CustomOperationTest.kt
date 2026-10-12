package io.liquidsoftware.acl

import io.liquidsoftware.acl.Operation.Manage
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CustomOperationTest {
    private data object Approve : Operation

    private data object Share : Operation

    // A custom operation can grant others by overriding covers.
    private data object Edit : Operation {
        override fun covers(requested: Operation): Boolean = requested == Edit || requested == Read || requested == Write
    }

    private val bob = User(id = "bob", isSystemAdmin = false)
    private val admin = User(id = "root", isSystemAdmin = true)
    private val invoice = Invoice(ownerId = "bob")

    private val acl = aclCatalog<User> {
        policy<Invoice> {
            allow(Manage) { user -> user.isSystemAdmin }
            allow(Approve) { user, invoice -> user.id == invoice.ownerId }
            allow(Edit) { user, invoice -> user.id == invoice.ownerId }
        }
    }

    @Test
    fun custom_operation_is_granted_by_its_own_rule() {
        assertTrue(acl.can(bob, Approve, invoice))
        assertFalse(acl.can(User(id = "alice", isSystemAdmin = false), Approve, invoice))
    }

    @Test
    fun custom_operation_without_a_rule_is_denied() {
        assertEquals(AccessDecision.Denied(NoMatchingAllowRule), acl.decide(bob, Share, invoice))
    }

    @Test
    fun manage_covers_custom_operations() {
        assertTrue(Manage.covers(Approve))
        assertTrue(acl.can(admin, Approve, invoice))
        assertTrue(acl.can(admin, Share, invoice))
    }

    @Test
    fun custom_operation_does_not_cover_built_ins_by_default() {
        assertFalse(Approve.covers(Read))
        assertFalse(Read.covers(Approve))
        assertFalse(Approve.covers(Share))
    }

    @Test
    fun custom_operation_can_cover_other_operations() {
        val access = acl.forSubject(bob)

        assertTrue(access.can(Edit, invoice))
        assertTrue(access.canRead(invoice))
        assertTrue(access.canWrite(invoice))
        assertFalse(access.canManage(invoice))
    }
}
