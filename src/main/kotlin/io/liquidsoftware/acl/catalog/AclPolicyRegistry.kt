package io.liquidsoftware.acl.catalog

import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.decision.AccessDecision
import io.liquidsoftware.acl.policy.AclPolicy
import kotlin.reflect.KClass

internal data class RegisteredPolicy<S : Any, R : Any>(
    val subjectType: KClass<S>,
    // The catalog routes by exact resource type, so this is registration metadata
    // rather than a runtime guard inside decide().
    val resourceType: KClass<R>,
    private val policy: AclPolicy<S, R>,
) {
    fun decide(subject: Any, operation: Operation, resource: Any): AccessDecision {
        val actualSubjectType = subject::class.qualifiedName ?: subject::class.simpleName ?: "unknown"

        require(subject::class == subjectType) {
            "Expected subject of type ${subjectType.qualifiedName ?: subjectType.simpleName ?: "unknown"}, got $actualSubjectType"
        }

        @Suppress("UNCHECKED_CAST")
        return policy.decide(subject as S, operation, resource as R)
    }
}

internal class AclPolicyRegistry private constructor(
    private val policies: Map<KClass<*>, RegisteredPolicy<*, *>>,
) {
    fun resolve(resource: Any): RegisteredPolicy<*, *>? = policies[resource::class]

    internal class Builder {
        private val policies = linkedMapOf<KClass<*>, RegisteredPolicy<*, *>>()

        fun <S : Any, R : Any> register(policy: AclPolicy<S, R>) {
            val resourceType = policy.resourceType
            check(resourceType !in policies) {
                "A policy is already registered for ${resourceType.qualifiedName ?: resourceType.simpleName ?: "unknown"}"
            }

            policies[resourceType] = RegisteredPolicy(
                subjectType = policy.subjectType,
                resourceType = policy.resourceType,
                policy = policy,
            )
        }

        fun build(): AclPolicyRegistry = AclPolicyRegistry(policies.toMap())
    }
}
