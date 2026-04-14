package io.liquidsoftware.acl.policy

import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.decision.AccessDecision
import io.liquidsoftware.acl.decision.AccessDecision.Denied
import io.liquidsoftware.acl.decision.AccessDecision.Granted
import io.liquidsoftware.acl.decision.NoMatchingAllowRule
import kotlin.reflect.KClass

@DslMarker
annotation class AclDsl

class AclPolicy<S : Any, R : Any> internal constructor(
    // The catalog routes by resource type, so only the resource type is part of the public surface.
    // The subject type is retained for internal validation at evaluation time.
    internal val subjectType: KClass<S>,
    val resourceType: KClass<R>,
    internal val rules: List<AclRule<S, R>>,
) {
    fun decide(subject: S, operation: Operation, resource: R): AccessDecision {
        val allowed = rules.any { rule ->
            rule.operation.covers(operation) && rule.matches(subject, resource)
        }

        return if (allowed) Granted else Denied(NoMatchingAllowRule)
    }
}

@AclDsl
class AclPolicyBuilder<S : Any, R : Any> {
    private val rules = mutableListOf<AclRule<S, R>>()

    fun allow(operation: Operation, predicate: (S) -> Boolean) {
        rules += AclRule.SubjectOnly(operation, predicate)
    }

    fun allow(operation: Operation, predicate: (S, R) -> Boolean) {
        rules += AclRule.SubjectAndResource(operation, predicate)
    }

    @PublishedApi
    internal fun build(
        subjectType: KClass<S>,
        resourceType: KClass<R>,
    ): AclPolicy<S, R> = AclPolicy(
        subjectType = subjectType,
        resourceType = resourceType,
        rules = rules.toList(),
    )
}

inline fun <reified S : Any, reified R : Any> aclPolicy(
    noinline block: AclPolicyBuilder<S, R>.() -> Unit,
): AclPolicy<S, R> = AclPolicyBuilder<S, R>().apply(block).build(S::class, R::class)
