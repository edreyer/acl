package io.liquidsoftware.acl

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Mirrors the 0.4 code in docs/migrating-to-0.4.md. If you change an example there, change it here too.
 */
class MigrationGuideExamplesTest {
    private val bob = User(id = "bob", isSystemAdmin = false)
    private val bobsBook = Book(userId = "bob")
    private val alicesBook = Book(userId = "alice")
    private val books = listOf(bobsBook, alicesBook)

    private val invoicePolicy = aclPolicy<User, Invoice> {
        allow(Operation.Read) { user, invoice -> user.id == invoice.ownerId }
    }

    private val acl = aclCatalog<User> {
        policy<Book> {
            allow(Operation.Read, Operation.Write) { user, book -> user.id == book.userId }
        }
        register(invoicePolicy)
    }

    @Test
    fun typed_catalog_with_inline_and_registered_policies() {
        assertTrue(acl.canRead(bob, bobsBook))
        assertTrue(acl.canWrite(bob, bobsBook))
        assertTrue(acl.canRead(bob, Invoice(ownerId = "bob")))
    }

    private sealed interface Principal

    private data class Member(val id: String) : Principal

    private data class ServiceAccount(val name: String) : Principal

    private data class Report(val title: String)

    @Test
    fun several_subject_types_share_a_sealed_supertype() {
        val principalAcl = aclCatalog<Principal> {
            policy<Book> {
                allow(Operation.Read) { principal, book -> principal is Member && principal.id == book.userId }
            }
            policy<Report> {
                allow(Operation.Read) { principal -> principal is ServiceAccount }
            }
        }

        assertTrue(principalAcl.canRead(Member("bob"), bobsBook))
        assertFalse(principalAcl.canRead(ServiceAccount("etl"), bobsBook))
        assertTrue(principalAcl.canRead(ServiceAccount("etl"), Report("daily")))
    }

    @Test
    fun collection_helper_replacements() {
        val access = acl.forSubject(bob)
        val op = Operation.Read

        assertFalse(books.all(access::canRead))
        assertFalse(books.all { access.can(op, it) })
        assertEquals(listOf(bobsBook), books.filter(access::canWrite))
        assertEquals(listOf(bobsBook), books.filter { access.can(op, it) })

        val (allowed, denied) = books.partition(access::canRead)
        assertEquals(listOf(bobsBook), allowed)
        assertEquals(listOf(alicesBook), denied)
        assertFalse(denied.isEmpty())

        val decisions = books.map { it to access.decide(op, it) }
        assertFalse(decisions.all { it.second.granted })
        assertEquals(AccessDecision.Denied(NoMatchingAllowRule(op, Book::class)), decisions[1].second)
        assertEquals(decisions.toMap(), books.associateWith { access.decide(op, it) })

        assertTrue(emptyList<Book>().all(access::canRead))
    }

    private data class Invoice2(val approverId: String)

    private data object Approve : Operation

    private fun operationNamed(name: String): Operation = when (name) {
        "Read" -> Operation.Read
        "Write" -> Operation.Write
        "Manage" -> Operation.Manage
        else -> error("Unknown operation: $name")
    }

    @Test
    fun custom_operations_and_operation_lookup() {
        val approvals = aclCatalog<User> {
            policy<Invoice2> {
                allow(Approve) { user, invoice -> user.id == invoice.approverId }
            }
        }

        assertTrue(approvals.can(bob, Approve, Invoice2(approverId = "bob")))
        assertEquals(Operation.Write, operationNamed("Write"))
        assertFailsWith<IllegalStateException> { operationNamed("Delete") }
    }

    private open class Document(val ownerId: String)

    private class Contract(ownerId: String) : Document(ownerId)

    @Test
    fun empty_subtype_policy_keeps_denying_the_subtype() {
        val documents = aclCatalog<User> {
            policy<Document> {
                allow(Operation.Read) { user, doc -> user.id == doc.ownerId }
            }
        }
        assertTrue(documents.canRead(bob, Contract("bob")))

        val withOverride = aclCatalog<User> {
            policy<Document> {
                allow(Operation.Read) { user, doc -> user.id == doc.ownerId }
            }
            policy<Contract> { }
        }
        assertFalse(withOverride.canRead(bob, Contract("bob")))
        assertTrue(withOverride.canRead(bob, Document("bob")))
    }
}
