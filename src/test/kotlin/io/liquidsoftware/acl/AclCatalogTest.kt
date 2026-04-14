package io.liquidsoftware.acl

import io.liquidsoftware.acl.catalog.aclCatalog
import io.liquidsoftware.acl.decision.AccessDecision
import io.liquidsoftware.acl.decision.NoPolicyRegistered
import io.liquidsoftware.acl.policy.aclPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AclCatalogTest {
    private val bookPolicy = aclPolicy<User, Book> {
        allow(Operation.Manage) { user -> user.isSystemAdmin }
        allow(Operation.Read) { user, book -> user.id == book.userId }
        allow(Operation.Write) { user, book -> user.id == book.userId }
    }

    private val invoicePolicy = aclPolicy<User, Invoice> {
        allow(Operation.Read) { user, invoice -> user.id == invoice.ownerId }
    }

    private val catalog = aclCatalog {
        register(bookPolicy)
        register(invoicePolicy)
    }

    @Test
    fun catalog_routes_to_the_matching_policy() {
        val bob = User(id = "bob", isSystemAdmin = false)
        val book = Book(userId = "bob")

        assertTrue(catalog.canRead(bob, book))
        assertTrue(catalog.canWrite(bob, book))
    }

    @Test
    fun catalog_supports_multiple_policies() {
        val bob = User(id = "bob", isSystemAdmin = false)
        val invoice = Invoice(ownerId = "bob")

        assertTrue(catalog.canRead(bob, invoice))
        assertFalse(catalog.canWrite(bob, invoice))
    }

    @Test
    fun unknown_resource_types_default_to_denied() {
        val bob = User(id = "bob", isSystemAdmin = false)

        assertEquals(
            AccessDecision.Denied(NoPolicyRegistered(String::class)),
            catalog.decide(bob, Operation.Read, "no policy"),
        )
    }

    @Test
    fun collection_helpers_work_as_expected() {
        val bob = User(id = "bob", isSystemAdmin = false)
        val books = listOf(
            Book(userId = "bob"),
            Book(userId = "alice"),
        )

        assertEquals(listOf(Book(userId = "bob")), catalog.filterReadableBy(bob, books))
        assertEquals(false, catalog.canReadAll(bob, books))

        val partition = catalog.partitionReadableBy(bob, books)
        assertEquals(listOf(Book(userId = "bob")), partition.allowed)
        assertEquals(listOf(Book(userId = "alice")), partition.denied)
        assertFalse(partition.allGranted)
    }

    @Test
    fun write_and_manage_collection_helpers_work_as_expected() {
        val bob = User(id = "bob", isSystemAdmin = false)
        val admin = User(id = "root", isSystemAdmin = true)
        val books = listOf(
            Book(userId = "bob"),
            Book(userId = "alice"),
        )

        assertEquals(listOf(Book(userId = "bob")), catalog.filterWritableBy(bob, books))
        assertEquals(false, catalog.canWriteAll(bob, books))

        val writePartition = catalog.partitionWritableBy(bob, books)
        assertEquals(listOf(Book(userId = "bob")), writePartition.allowed)
        assertEquals(listOf(Book(userId = "alice")), writePartition.denied)
        assertFalse(writePartition.allGranted)

        assertEquals(books, catalog.filterManageableBy(admin, books))
        assertTrue(catalog.canManageAll(admin, books))

        val managePartition = catalog.partitionManageableBy(admin, books)
        assertEquals(books, managePartition.allowed)
        assertEquals(emptyList(), managePartition.denied)
        assertTrue(managePartition.allGranted)
    }

    @Test
    fun read_write_and_manage_all_are_true_for_fully_accessible_collection() {
        val admin = User(id = "root", isSystemAdmin = true)
        val books = listOf(
            Book(userId = "bob"),
            Book(userId = "alice"),
        )

        assertTrue(catalog.canReadAll(admin, books))
        assertTrue(catalog.canWriteAll(admin, books))
        assertTrue(catalog.canManageAll(admin, books))
    }

    @Test
    fun decideAll_preserves_per_item_decisions() {
        val bob = User(id = "bob", isSystemAdmin = false)
        val books = listOf(
            Book(userId = "bob"),
            Book(userId = "alice"),
        )

        val result = catalog.decideAll(bob, Operation.Read, books)

        assertFalse(result.allGranted)
        assertEquals(2, result.decisions.size)
        assertTrue(result.decisions[0].granted)
        assertFalse(result.decisions[1].granted)
    }

    @Test
    fun decideAll_on_empty_collection_is_empty_and_granted() {
        val bob = User(id = "bob", isSystemAdmin = false)

        val result = catalog.decideAll(bob, Operation.Read, emptyList<Book>())

        assertTrue(result.allGranted)
        assertTrue(result.decisions.isEmpty())
        assertTrue(result.allowed.isEmpty())
        assertTrue(result.denied.isEmpty())
        assertTrue(result.partition().allGranted)
    }

    @Test
    fun can_read_all_on_empty_collection_is_true() {
        val bob = User(id = "bob", isSystemAdmin = false)

        assertTrue(catalog.canReadAll(bob, emptyList<Book>()))
    }

    @Test
    fun can_write_all_and_can_manage_all_on_empty_collection_are_true() {
        val bob = User(id = "bob", isSystemAdmin = false)

        assertTrue(catalog.canWriteAll(bob, emptyList<Book>()))
        assertTrue(catalog.canManageAll(bob, emptyList<Book>()))
    }

    @Test
    fun empty_collection_partition_helpers_are_empty_and_granted() {
        val bob = User(id = "bob", isSystemAdmin = false)

        val writePartition = catalog.partitionWritableBy(bob, emptyList<Book>())
        assertTrue(writePartition.allGranted)
        assertTrue(writePartition.allowed.isEmpty())
        assertTrue(writePartition.denied.isEmpty())

        val managePartition = catalog.partitionManageableBy(bob, emptyList<Book>())
        assertTrue(managePartition.allGranted)
        assertTrue(managePartition.allowed.isEmpty())
        assertTrue(managePartition.denied.isEmpty())
    }

    @Test
    fun duplicate_registration_is_rejected() {
        assertFailsWith<IllegalStateException> {
            aclCatalog {
                register(bookPolicy)
                register(bookPolicy)
            }
        }
    }

    @Test
    fun wrong_subject_type_fails_fast() {
        val book = Book(userId = "bob")

        val exception = assertFailsWith<IllegalArgumentException> {
            catalog.decide("bob", Operation.Read, book)
        }

        assertTrue(exception.message!!.contains("got kotlin.String"))
    }

    @Test
    fun duplicate_registration_is_rejected_for_distinct_policy_instances_of_same_resource_type() {
        val otherBookPolicy = aclPolicy<User, Book> {
            allow(Operation.Read) { user, book -> user.id == book.userId }
        }

        assertFailsWith<IllegalStateException> {
            aclCatalog {
                register(bookPolicy)
                register(otherBookPolicy)
            }
        }
    }

    @Test
    fun empty_catalog_denies_unknown_resources() {
        val bob = User(id = "bob", isSystemAdmin = false)
        val emptyCatalog = aclCatalog { }

        assertEquals(
            AccessDecision.Denied(NoPolicyRegistered(String::class)),
            emptyCatalog.decide(bob, Operation.Read, "no policy"),
        )
    }
}
