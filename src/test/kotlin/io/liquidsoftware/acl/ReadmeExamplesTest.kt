package io.liquidsoftware.acl

import io.liquidsoftware.acl.Operation.Manage
import io.liquidsoftware.acl.Operation.Read
import io.liquidsoftware.acl.Operation.Write
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Mirrors the examples in README.md. If you change an example there, change it here too.
 */
class ReadmeExamplesTest {
    private val acl = aclCatalog<User> {
        policy<Book> {
            allow(Manage) { user -> user.isSystemAdmin }
            allow(Read, Write) { user, book -> user.id == book.userId }
        }
    }

    private val bob = User(id = "bob", isSystemAdmin = false)
    private val admin = User(id = "root", isSystemAdmin = true)
    private val book = Book(userId = "bob")

    @Test
    fun quick_start() {
        assertTrue(acl.canRead(bob, book))
        assertTrue(acl.canWrite(bob, book))
        assertTrue(acl.canManage(admin, book))

        val message = when (val decision = acl.decide(bob, Read, Book(userId = "alice"))) {
            AccessDecision.Granted -> "granted"
            is AccessDecision.Denied -> decision.reason.message
        }
        assertEquals("No rule allows Read on io.liquidsoftware.acl.Book", message)
    }

    @Test
    fun checking_many_resources() {
        val books = listOf(book, Book(userId = "alice"))
        val access = acl.forSubject(bob)

        assertTrue(access.canRead(book))
        assertEquals(listOf(book), books.filter(access::canRead))
        val (editable, readOnly) = books.partition(access::canWrite)
        assertEquals(listOf(book), editable)
        assertEquals(listOf(Book(userId = "alice")), readOnly)
        assertFalse(books.all(access::canManage))
        assertEquals(
            mapOf(book to AccessDecision.Granted, Book(userId = "alice") to AccessDecision.Denied(NoMatchingAllowRule(Read, Book::class))),
            books.associateWith { access.decide(Read, it) },
        )
    }

    private data class Invoice(val approverId: String)

    private data object Approve : Operation

    private data object Share : Operation

    private data object Edit : Operation {
        override fun covers(requested: Operation) = requested == Edit || requested == Read || requested == Write
    }

    @Test
    fun custom_operations() {
        val acl = aclCatalog<User> {
            policy<Invoice> {
                allow(Manage) { user -> user.isSystemAdmin }
                allow(Approve) { user, invoice -> user.id == invoice.approverId }
            }
        }
        val invoice = Invoice(approverId = "bob")

        assertTrue(acl.can(bob, Approve, invoice))
        assertFalse(acl.forSubject(bob).can(Share, invoice))
        assertFalse(acl.can(admin, Approve, invoice))
        assertFalse(acl.forSubject(admin).can(Share, invoice))
        assertTrue(Edit.covers(Read))
        assertTrue(Edit.covers(Write))
        assertFalse(Edit.covers(Manage))
    }

    private sealed interface Principal {
        val id: String
    }

    private data class Member(override val id: String) : Principal
    private data class Admin(override val id: String) : Principal

    private open class Document(val ownerId: String)
    private class Contract(ownerId: String) : Document(ownerId)
    private class SecretDocument(ownerId: String) : Document(ownerId)

    @Test
    fun type_hierarchies() {
        val acl = aclCatalog<Principal> {
            policy<Document> {
                allow(Manage) { it is Admin }
                allow(Read) { principal, doc -> principal.id == doc.ownerId }
            }
            policy<SecretDocument> {
                allow(Manage) { it is Admin }
            }
        }

        assertTrue(acl.canRead(Member("bob"), Contract("bob")))
        assertTrue(acl.hasPolicyFor(Contract::class))
        assertFalse(acl.canRead(Member("bob"), SecretDocument("bob")))
        assertTrue(acl.canRead(Admin("root"), SecretDocument("bob")))
    }
}
