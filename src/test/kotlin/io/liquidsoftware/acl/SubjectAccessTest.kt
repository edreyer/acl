package io.liquidsoftware.acl

import io.liquidsoftware.acl.Operation.Manage
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class SubjectAccessTest {
    private val catalog = aclCatalog<User> {
        policy<Book> {
            allow(Manage) { user -> user.isSystemAdmin }
            allow(Read) { user, book -> user.id == book.userId }
        }
    }

    private val bob = User(id = "bob", isSystemAdmin = false)
    private val admin = User(id = "root", isSystemAdmin = true)
    private val bobsBook = Book(userId = "bob")
    private val alicesBook = Book(userId = "alice")
    private val books = listOf(bobsBook, alicesBook)

    @Test
    fun checks_delegate_to_the_catalog_for_the_bound_subject() {
        val access = catalog.forSubject(bob)

        assertSame(bob, access.subject)
        assertTrue(access.canRead(bobsBook))
        assertFalse(access.canRead(alicesBook))
        assertFalse(access.canWrite(bobsBook))
        assertFalse(access.canManage(bobsBook))
        assertEquals(catalog.decide(bob, Read, alicesBook), access.decide(Read, alicesBook))
        assertEquals(catalog.can(bob, Write, bobsBook), access.can(Write, bobsBook))
    }

    @Test
    fun checks_compose_with_collection_functions() {
        val access = catalog.forSubject(bob)

        assertEquals(listOf(bobsBook), books.filter(access::canRead))
        assertEquals(listOf(bobsBook) to listOf(alicesBook), books.partition(access::canRead))
        assertFalse(books.all(access::canRead))
        assertTrue(emptyList<Book>().all(access::canRead))
    }

    @Test
    fun manage_grants_every_operation_across_a_collection() {
        val access = catalog.forSubject(admin)

        assertTrue(books.all(access::canRead))
        assertTrue(books.all(access::canWrite))
        assertTrue(books.all(access::canManage))
    }
}
