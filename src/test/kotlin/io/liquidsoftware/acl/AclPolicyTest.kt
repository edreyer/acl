package io.liquidsoftware.acl

import io.liquidsoftware.acl.decision.AccessDecision
import io.liquidsoftware.acl.decision.NoMatchingAllowRule
import io.liquidsoftware.acl.policy.aclPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AclPolicyTest {
    private val policy = aclPolicy<User, Book> {
        allow(Operation.Manage) { user -> user.isSystemAdmin }
        allow(Operation.Read) { user, book -> user.id == book.userId }
        allow(Operation.Write) { user, book -> user.id == book.userId }
    }

    @Test
    fun ownership_rule_allows_read_and_write() {
        val bob = User(id = "bob", isSystemAdmin = false)
        val book = Book(userId = "bob")

        assertTrue(policy.decide(bob, Operation.Read, book).granted)
        assertTrue(policy.decide(bob, Operation.Write, book).granted)
    }

    @Test
    fun non_owner_is_denied_read_and_write() {
        val bob = User(id = "bob", isSystemAdmin = false)
        val book = Book(userId = "alice")

        assertEquals(
            AccessDecision.Denied(NoMatchingAllowRule),
            policy.decide(bob, Operation.Read, book),
        )
        assertEquals(
            AccessDecision.Denied(NoMatchingAllowRule),
            policy.decide(bob, Operation.Write, book),
        )
    }

    @Test
    fun admin_rule_allows_manage_and_inherited_read_write() {
        val admin = User(id = "root", isSystemAdmin = true)
        val book = Book(userId = "someone-else")

        assertTrue(policy.decide(admin, Operation.Manage, book).granted)
        assertTrue(policy.decide(admin, Operation.Read, book).granted)
        assertTrue(policy.decide(admin, Operation.Write, book).granted)
    }

    @Test
    fun unmatched_access_is_denied() {
        val bob = User(id = "bob", isSystemAdmin = false)
        val book = Book(userId = "alice")

        assertEquals(
            AccessDecision.Denied(NoMatchingAllowRule),
            policy.decide(bob, Operation.Manage, book),
        )
    }

    @Test
    fun empty_policy_denies_all_access() {
        val emptyPolicy = aclPolicy<User, Book> { }
        val bob = User(id = "bob", isSystemAdmin = false)
        val book = Book(userId = "bob")

        assertEquals(
            AccessDecision.Denied(NoMatchingAllowRule),
            emptyPolicy.decide(bob, Operation.Read, book),
        )
        assertEquals(
            AccessDecision.Denied(NoMatchingAllowRule),
            emptyPolicy.decide(bob, Operation.Write, book),
        )
        assertEquals(
            AccessDecision.Denied(NoMatchingAllowRule),
            emptyPolicy.decide(bob, Operation.Manage, book),
        )
    }

    @Test
    fun read_only_policy_allows_only_read() {
        val readOnlyPolicy = aclPolicy<User, Book> {
            allow(Operation.Read) { user, book -> user.id == book.userId }
        }
        val bob = User(id = "bob", isSystemAdmin = false)
        val book = Book(userId = "bob")

        assertTrue(readOnlyPolicy.decide(bob, Operation.Read, book).granted)
        assertEquals(
            AccessDecision.Denied(NoMatchingAllowRule),
            readOnlyPolicy.decide(bob, Operation.Write, book),
        )
        assertEquals(
            AccessDecision.Denied(NoMatchingAllowRule),
            readOnlyPolicy.decide(bob, Operation.Manage, book),
        )
    }

    @Test
    fun write_only_policy_allows_only_write() {
        val writeOnlyPolicy = aclPolicy<User, Book> {
            allow(Operation.Write) { user, book -> user.id == book.userId }
        }
        val bob = User(id = "bob", isSystemAdmin = false)
        val book = Book(userId = "bob")

        assertEquals(
            AccessDecision.Denied(NoMatchingAllowRule),
            writeOnlyPolicy.decide(bob, Operation.Read, book),
        )
        assertTrue(writeOnlyPolicy.decide(bob, Operation.Write, book).granted)
        assertEquals(
            AccessDecision.Denied(NoMatchingAllowRule),
            writeOnlyPolicy.decide(bob, Operation.Manage, book),
        )
    }

    @Test
    fun manage_only_policy_allows_manage_and_inherited_lower_operations() {
        val manageOnlyPolicy = aclPolicy<User, Book> {
            allow(Operation.Manage) { user -> user.isSystemAdmin }
        }
        val admin = User(id = "root", isSystemAdmin = true)
        val book = Book(userId = "bob")

        assertTrue(manageOnlyPolicy.decide(admin, Operation.Manage, book).granted)
        assertTrue(manageOnlyPolicy.decide(admin, Operation.Read, book).granted)
        assertTrue(manageOnlyPolicy.decide(admin, Operation.Write, book).granted)
    }
}
