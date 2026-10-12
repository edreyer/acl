package io.liquidsoftware.acl

import io.liquidsoftware.acl.Operation.Manage
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Build-sanity test for the public DSL and catalog wiring.
 * This intentionally overlaps with behavioral tests.
 */
class AclApiSmokeTest {
    @Test
    fun public_api_wires_policy_builder_into_catalog() {
        val acl = aclCatalog<User> {
            policy<Book> {
                allow(Manage) { user -> user.isSystemAdmin }
                allow(Read, Write) { user, book -> user.id == book.userId }
            }
        }

        val bob = User(id = "bob", isSystemAdmin = false)
        val admin = User(id = "root", isSystemAdmin = true)
        val book = Book(userId = "bob")
        val books = listOf(book, Book(userId = "alice"))

        assertTrue(acl.canRead(bob, book))
        assertTrue(acl.canWrite(bob, book))
        assertTrue(acl.canManage(admin, book))

        val access = acl.forSubject(bob)
        assertEquals(listOf(book), books.filter(access::canRead))
    }
}
