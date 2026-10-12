package io.liquidsoftware.acl

import java.util.concurrent.ConcurrentHashMap
import kotlin.reflect.KClass

internal class AclPolicyRegistry<S : Any> private constructor(
    private val policies: Map<Class<*>, AclPolicy<S, *>>,
) {
    private val resolved = ConcurrentHashMap<Class<*>, Resolution<S>>()

    fun decide(subject: S, operation: Operation, resource: Any): AccessDecision {
        val policy = resolve(resource) ?: return AccessDecision.Denied(NoPolicyRegistered(resource::class))

        // The registry only routes a resource to a policy whose resource type it is an instance of.
        @Suppress("UNCHECKED_CAST")
        return (policy as AclPolicy<S, Any>).decide(subject, operation, resource)
    }

    private fun resolve(resource: Any): AclPolicy<S, *>? =
        resolved.getOrPut(resource.javaClass) { Resolution(mostSpecificPolicyFor(resource.javaClass)) }.policy

    // Picks the policy registered for the closest supertype of the resource (including the type itself).
    // Two matching policies where neither type is a subtype of the other is a configuration error.
    private fun mostSpecificPolicyFor(type: Class<*>): AclPolicy<S, *>? {
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

    private class Resolution<S : Any>(val policy: AclPolicy<S, *>?)

    internal class Builder<S : Any> {
        private val policies = linkedMapOf<Class<*>, AclPolicy<S, *>>()

        fun register(policy: AclPolicy<S, *>) {
            val resourceType = policy.resourceType
            val key = resourceType.javaObjectType
            check(key !in policies) {
                "A policy is already registered for ${resourceType.displayName()}"
            }
            policies[key] = policy
        }

        fun build(): AclPolicyRegistry<S> = AclPolicyRegistry(policies.toMap())
    }
}

private fun KClass<*>.displayName(): String = qualifiedName ?: simpleName ?: "unknown"
