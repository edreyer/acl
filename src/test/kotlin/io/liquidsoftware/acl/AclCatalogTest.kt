package io.liquidsoftware.acl

import io.liquidsoftware.acl.Operation.Manage
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AclCatalogTest {
    private val bookPolicy = aclPolicy<User, Book> {
        allow(Manage) { user -> user.isSystemAdmin }
        allow(Read, Write) { user, book -> user.id == book.userId }
    }

    private val catalog = aclCatalog<User> {
        register(bookPolicy)
        policy<Invoice> {
            allow(Read) { user, invoice -> user.id == invoice.ownerId }
        }
    }

    private val bob = User(id = "bob", isSystemAdmin = false)
    private val admin = User(id = "root", isSystemAdmin = true)

    @Test
    fun catalog_routes_to_the_matching_policy() {
        val book = Book(userId = "bob")

        assertTrue(catalog.canRead(bob, book))
        assertTrue(catalog.canWrite(bob, book))
        assertFalse(catalog.canManage(bob, book))
    }

    @Test
    fun registered_and_inline_policies_can_be_mixed() {
        val invoice = Invoice(ownerId = "bob")

        assertTrue(catalog.canRead(bob, invoice))
        assertFalse(catalog.canWrite(bob, invoice))
    }

    @Test
    fun can_matches_decide() {
        val book = Book(userId = "alice")

        assertEquals(catalog.decide(bob, Read, book).granted, catalog.can(bob, Read, book))
        assertEquals(AccessDecision.Denied(NoMatchingAllowRule), catalog.decide(bob, Read, book))
        assertEquals(AccessDecision.Granted, catalog.decide(admin, Read, book))
    }

    @Test
    fun unknown_resource_types_default_to_denied() {
        assertEquals(
            AccessDecision.Denied(NoPolicyRegistered(String::class)),
            catalog.decide(bob, Read, "no policy"),
        )
    }

    @Test
    fun empty_catalog_denies_unknown_resources() {
        val emptyCatalog = aclCatalog<User> { }

        assertEquals(
            AccessDecision.Denied(NoPolicyRegistered(String::class)),
            emptyCatalog.decide(bob, Read, "no policy"),
        )
    }

    @Test
    fun duplicate_registration_is_rejected() {
        assertFailsWith<IllegalStateException> {
            aclCatalog<User> {
                register(bookPolicy)
                register(bookPolicy)
            }
        }
    }

    @Test
    fun duplicate_registration_is_rejected_for_distinct_policy_instances_of_same_resource_type() {
        assertFailsWith<IllegalStateException> {
            aclCatalog<User> {
                register(bookPolicy)
                policy<Book> {
                    allow(Read) { user, book -> user.id == book.userId }
                }
            }
        }
    }

    @Test
    fun policy_written_for_a_supertype_of_the_subject_can_be_registered() {
        val publicBooks = aclPolicy<Any, Book> {
            allow(Read) { _ -> true }
        }

        val publicCatalog = aclCatalog<User> {
            register(publicBooks)
        }

        assertTrue(publicCatalog.canRead(bob, Book(userId = "alice")))
    }
}
