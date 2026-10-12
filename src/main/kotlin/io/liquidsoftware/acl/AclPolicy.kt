package io.liquidsoftware.acl

import io.liquidsoftware.acl.AccessDecision.Denied
import io.liquidsoftware.acl.AccessDecision.Granted
import kotlin.reflect.KClass

@DslMarker
public annotation class AclDsl

/**
 * The access rules for one resource type. Build one with [aclPolicy], or inline in [aclCatalog] with
 * [AclCatalogBuilder.policy].
 */
public class AclPolicy<in S : Any, R : Any> internal constructor(
    internal val resourceType: KClass<R>,
    private val rules: List<AclRule<S, R>>,
) {
    public fun decide(subject: S, operation: Operation, resource: R): AccessDecision =
        if (rules.any { it.matches(subject, operation, resource) }) Granted else Denied(NoMatchingAllowRule)
}

@AclDsl
public class AclPolicyBuilder<S : Any, R : Any> @PublishedApi internal constructor() {
    private val rules = mutableListOf<AclRule<S, R>>()

    /** Allows [operation] (and any [more] operations) when the subject alone satisfies [predicate]. */
    public fun allow(operation: Operation, vararg more: Operation, predicate: (S) -> Boolean) {
        rules += AclRule(setOf(operation, *more)) { subject, _ -> predicate(subject) }
    }

    /** Allows [operation] (and any [more] operations) when the subject and resource satisfy [predicate]. */
    public fun allow(operation: Operation, vararg more: Operation, predicate: (S, R) -> Boolean) {
        rules += AclRule(setOf(operation, *more), predicate)
    }

    @PublishedApi
    internal fun build(resourceType: KClass<R>): AclPolicy<S, R> = AclPolicy(resourceType, rules.toList())
}

public inline fun <S : Any, reified R : Any> aclPolicy(
    noinline block: AclPolicyBuilder<S, R>.() -> Unit,
): AclPolicy<S, R> = AclPolicyBuilder<S, R>().apply(block).build(R::class)
