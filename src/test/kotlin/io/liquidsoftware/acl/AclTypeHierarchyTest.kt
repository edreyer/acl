package io.liquidsoftware.acl

import io.liquidsoftware.acl.catalog.aclCatalog
import io.liquidsoftware.acl.decision.AccessDecision
import io.liquidsoftware.acl.decision.NoPolicyRegistered
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AclTypeHierarchyTest {
    private sealed interface Principal {
        val id: String
    }

    private data class Member(override val id: String) : Principal
    private data class Admin(override val id: String) : Principal

    private open class Document(val ownerId: String)
    private class SecretDocument(ownerId: String) : Document(ownerId)
    private class Contract(ownerId: String) : Document(ownerId)

    private interface Shareable
    private interface Archivable
    private class Report : Shareable, Archivable

    private val catalog = aclCatalog {
        policy<Principal, Document> {
            allow(Operation.Manage) { principal -> principal is Admin }
            allow(Operation.Read) { principal, document -> principal.id == document.ownerId }
        }
        policy<Principal, SecretDocument> {
            allow(Operation.Manage) { principal -> principal is Admin }
        }
    }

    @Test
    fun subtype_of_the_subject_type_is_accepted() {
        assertTrue(catalog.canRead(Member("bob"), Document("bob")))
        assertFalse(catalog.canRead(Member("bob"), Document("alice")))
        assertTrue(catalog.canManage(Admin("root"), Document("alice")))
    }

    @Test
    fun subtype_resource_falls_back_to_the_supertype_policy() {
        assertTrue(catalog.canRead(Member("bob"), Contract("bob")))
        assertFalse(catalog.canWrite(Member("bob"), Contract("bob")))
    }

    @Test
    fun most_specific_policy_wins() {
        // SecretDocument has its own policy, which grants owners nothing.
        assertFalse(catalog.canRead(Member("bob"), SecretDocument("bob")))
        assertTrue(catalog.canRead(Admin("root"), SecretDocument("bob")))
    }

    @Test
    fun repeated_lookups_return_the_same_decision() {
        repeat(3) {
            assertTrue(catalog.canRead(Member("bob"), Contract("bob")))
        }
    }

    @Test
    fun unrelated_resource_types_are_still_denied() {
        assertEquals(
            AccessDecision.Denied(NoPolicyRegistered(String::class)),
            catalog.decide(Member("bob"), Operation.Read, "no policy"),
        )
    }

    @Test
    fun policy_registered_for_an_interface_matches_implementations() {
        val interfaceCatalog = aclCatalog {
            policy<Principal, Shareable> {
                allow(Operation.Read) { _ -> true }
            }
        }

        assertTrue(interfaceCatalog.canRead(Member("bob"), Report()))
    }

    @Test
    fun ambiguous_policies_fail_fast() {
        val ambiguousCatalog = aclCatalog {
            policy<Principal, Shareable> {
                allow(Operation.Read) { _ -> true }
            }
            policy<Principal, Archivable> {
                allow(Operation.Read) { _ -> false }
            }
        }

        val exception = assertFailsWith<IllegalStateException> {
            ambiguousCatalog.canRead(Member("bob"), Report())
        }

        assertTrue(exception.message!!.contains("Ambiguous"))
    }

    @Test
    fun boxed_primitive_resources_match_supertype_policies() {
        val numberCatalog = aclCatalog {
            policy<Principal, Number> {
                allow(Operation.Read) { _ -> true }
            }
        }

        assertTrue(numberCatalog.canRead(Member("bob"), 42))
    }
}
