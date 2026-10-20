package io.liquidsoftware.acl

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

    private interface Asset
    private interface Printable : Asset
    private interface Exportable : Asset
    private class Invoice : Printable, Exportable

    private val catalog = aclCatalog<Principal> {
        policy<Document> {
            allow(Operation.Manage) { principal -> principal is Admin }
            allow(Operation.Read) { principal, document -> principal.id == document.ownerId }
        }
        policy<SecretDocument> {
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
        val interfaceCatalog = aclCatalog<Principal> {
            policy<Shareable> {
                allow(Operation.Read) { _ -> true }
            }
        }

        assertTrue(interfaceCatalog.canRead(Member("bob"), Report()))
    }

    @Test
    fun ambiguous_policies_deny_with_a_reason() {
        val ambiguousCatalog = aclCatalog<Principal> {
            policy<Shareable> {
                allow(Operation.Read) { _ -> true }
            }
            policy<Archivable> {
                allow(Operation.Read) { _ -> false }
            }
        }

        repeat(2) {
            val decision = ambiguousCatalog.decide(Member("bob"), Operation.Read, Report())
            assertEquals(
                AccessDecision.Denied(AmbiguousPolicy(Report::class, listOf(Shareable::class, Archivable::class))),
                decision,
            )
        }
        assertFalse(ambiguousCatalog.canRead(Member("bob"), Report()))
    }

    @Test
    fun ambiguous_reason_names_only_the_conflicting_types() {
        val ambiguousCatalog = aclCatalog<Principal> {
            policy<Asset> {
                allow(Operation.Read) { _ -> true }
            }
            policy<Printable> {
                allow(Operation.Read) { _ -> true }
            }
            policy<Exportable> {
                allow(Operation.Read) { _ -> true }
            }
        }

        assertEquals(
            AccessDecision.Denied(AmbiguousPolicy(Invoice::class, listOf(Printable::class, Exportable::class))),
            ambiguousCatalog.decide(Member("bob"), Operation.Read, Invoice()),
        )
    }

    @Test
    fun ambiguity_is_resolved_by_a_policy_for_the_concrete_type() {
        val resolvedCatalog = aclCatalog<Principal> {
            policy<Shareable> {
                allow(Operation.Read) { _ -> true }
            }
            policy<Archivable> {
                allow(Operation.Read) { _ -> false }
            }
            policy<Report> {
                allow(Operation.Read) { principal -> principal is Admin }
            }
        }

        assertTrue(resolvedCatalog.canRead(Admin("root"), Report()))
        assertFalse(resolvedCatalog.canRead(Member("bob"), Report()))
    }

    @Test
    fun policy_for_any_is_rejected() {
        val exception = assertFailsWith<IllegalArgumentException> {
            aclCatalog<Principal> {
                policy<Any> {
                    allow(Operation.Read) { _ -> true }
                }
            }
        }

        assertTrue(exception.message!!.contains("Any"))
    }

    @Test
    fun registered_policy_for_any_is_rejected() {
        val anyPolicy = aclPolicy<Principal, Any> { allow(Operation.Read) { _ -> true } }

        assertFailsWith<IllegalArgumentException> {
            aclCatalog<Principal> { register(anyPolicy) }
        }
    }

    @Test
    fun boxed_primitive_resources_match_supertype_policies() {
        val numberCatalog = aclCatalog<Principal> {
            policy<Number> {
                allow(Operation.Read) { _ -> true }
            }
        }

        assertTrue(numberCatalog.canRead(Member("bob"), 42))
    }
}
