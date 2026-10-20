package io.liquidsoftware.acl

import kotlin.reflect.KClass

internal class AclPolicyRegistry<S : Any> private constructor(
    private val policies: Map<Class<*>, AclPolicy<S, *>>,
) {
    // ClassValue caches per class without keeping the class (or its classloader) reachable.
    private val resolved = object : ClassValue<Route<S>>() {
        override fun computeValue(type: Class<*>): Route<S> = mostSpecificPolicyFor(type)
    }

    fun decide(subject: S, operation: Operation, resource: Any): AccessDecision =
        when (val route = route(resource.javaClass)) {
            Route.None -> AccessDecision.Denied(NoPolicyRegistered(resource::class))
            is Route.Ambiguous -> AccessDecision.Denied(AmbiguousPolicy(resource::class, route.candidates))
            is Route.To -> {
                // The registry only routes a resource to a policy whose resource type it is an instance of.
                @Suppress("UNCHECKED_CAST")
                (route.policy as AclPolicy<S, Any>).decide(subject, operation, resource)
            }
        }

    private fun route(type: Class<*>): Route<S> = resolved.get(type)

    // Picks the policy registered for the closest supertype of the resource (including the type itself).
    // Only the most specific candidates (those with no matching subtype) can win; more than one is ambiguous.
    private fun mostSpecificPolicyFor(type: Class<*>): Route<S> {
        val candidates = policies.keys.filter { it.isAssignableFrom(type) }
        if (candidates.isEmpty()) return Route.None

        val mostSpecific = candidates.filter { candidate ->
            candidates.none { other -> other != candidate && candidate.isAssignableFrom(other) }
        }

        return mostSpecific.singleOrNull()?.let { Route.To(policies.getValue(it)) }
            ?: Route.Ambiguous(mostSpecific.map { it.kotlin })
    }

    private sealed interface Route<out S : Any> {
        data object None : Route<Nothing>

        class Ambiguous(val candidates: List<KClass<*>>) : Route<Nothing>

        class To<S : Any>(val policy: AclPolicy<S, *>) : Route<S>
    }

    internal class Builder<S : Any> {
        private val policies = linkedMapOf<Class<*>, AclPolicy<S, *>>()

        fun register(policy: AclPolicy<S, *>) {
            val resourceType = policy.resourceType
            val key = resourceType.javaObjectType
            require(key != Any::class.javaObjectType) {
                "A policy for Any would apply to every resource without its own policy, replacing default deny. " +
                    "Register policies for specific resource types instead."
            }
            check(key !in policies) {
                "A policy is already registered for ${resourceType.displayName()}"
            }
            policies[key] = policy
        }

        fun build(): AclPolicyRegistry<S> = AclPolicyRegistry(policies.toMap())
    }
}

internal fun KClass<*>.displayName(): String = qualifiedName ?: simpleName ?: "unknown"
