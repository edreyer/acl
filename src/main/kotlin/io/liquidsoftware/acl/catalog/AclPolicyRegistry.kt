package io.liquidsoftware.acl.catalog

import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.decision.AccessDecision
import io.liquidsoftware.acl.policy.AclPolicy
import java.util.concurrent.ConcurrentHashMap
import kotlin.reflect.KClass

internal data class RegisteredPolicy<S : Any, R : Any>(
    val subjectType: KClass<S>,
    // The registry routes resources to this policy by type, so this is registration metadata
    // rather than a runtime guard inside decide().
    val resourceType: KClass<R>,
    private val policy: AclPolicy<S, R>,
) {
    fun decide(subject: Any, operation: Operation, resource: Any): AccessDecision {
        require(subjectType.isInstance(subject)) {
            "Expected subject of type ${subjectType.displayName()}, got ${subject::class.displayName()}"
        }

        @Suppress("UNCHECKED_CAST")
        return policy.decide(subject as S, operation, resource as R)
    }
}

internal class AclPolicyRegistry private constructor(
    private val policies: Map<Class<*>, RegisteredPolicy<*, *>>,
) {
    private val resolved = ConcurrentHashMap<Class<*>, Resolution>()

    fun resolve(resource: Any): RegisteredPolicy<*, *>? =
        resolved.getOrPut(resource.javaClass) { Resolution(mostSpecificPolicyFor(resource.javaClass)) }.policy

    // Picks the policy registered for the closest supertype of the resource (including the type itself).
    // Two matching policies where neither type is a subtype of the other is a configuration error.
    private fun mostSpecificPolicyFor(type: Class<*>): RegisteredPolicy<*, *>? {
        val candidates = policies.keys.filter { it.isAssignableFrom(type) }
        if (candidates.isEmpty()) return null

        val mostSpecific = candidates.singleOrNull { candidate ->
            candidates.all { other -> other.isAssignableFrom(candidate) }
        }

        checkNotNull(mostSpecific) {
            "Ambiguous policies for ${type.name}: ${candidates.joinToString { it.name }}. " +
                "Register a policy for ${type.name} or one of its supertypes that is more specific than all of these."
        }

        return policies.getValue(mostSpecific)
    }

    private class Resolution(val policy: RegisteredPolicy<*, *>?)

    internal class Builder {
        private val policies = linkedMapOf<Class<*>, RegisteredPolicy<*, *>>()

        fun <S : Any, R : Any> register(policy: AclPolicy<S, R>) {
            val resourceType = policy.resourceType
            val key = resourceType.javaObjectType
            check(key !in policies) {
                "A policy is already registered for ${resourceType.displayName()}"
            }

            policies[key] = RegisteredPolicy(
                subjectType = policy.subjectType,
                resourceType = policy.resourceType,
                policy = policy,
            )
        }

        fun build(): AclPolicyRegistry = AclPolicyRegistry(policies.toMap())
    }
}

private fun KClass<*>.displayName(): String = qualifiedName ?: simpleName ?: "unknown"
