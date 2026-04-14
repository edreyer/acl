package io.liquidsoftware.acl

import io.liquidsoftware.acl.catalog.aclCatalog
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Build-sanity test for the public DSL and catalog wiring.
 * This intentionally overlaps with behavioral tests.
 */
class AclApiSmokeTest {
    @Test
    fun public_api_wires_policy_builder_into_catalog() {
        val catalog = aclCatalog {
            policy<User, Book> {
                allow(Operation.Manage) { user -> user.isSystemAdmin }
                allow(Operation.Read) { user, book -> user.id == book.userId }
                allow(Operation.Write) { user, book -> user.id == book.userId }
            }
        }

        val bob = User(id = "bob", isSystemAdmin = false)
        val admin = User(id = "root", isSystemAdmin = true)
        val book = Book(userId = "bob")

        assertTrue(catalog.canRead(bob, book))
        assertTrue(catalog.canWrite(bob, book))
        assertTrue(catalog.canManage(admin, book))
        assertTrue(catalog.canReadAll(bob, listOf(book)))
    }
}
