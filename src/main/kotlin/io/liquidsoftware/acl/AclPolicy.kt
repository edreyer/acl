package io.liquidsoftware.acl

import io.liquidsoftware.acl.AccessDecision.Denied
import io.liquidsoftware.acl.AccessDecision.Granted
import kotlin.reflect.KClass

/** Marks the catalog and policy builders, so code inside a `policy { }` block can't implicitly call the enclosing catalog builder. */
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
    /**
     * Grants [operation] when any rule for an operation that covers it matches [subject] and [resource], otherwise
     * denies with [NoMatchingAllowRule] naming [operation] and the resource's class. Exceptions thrown by rules propagate to the caller.
     */
    public fun decide(subject: S, operation: Operation, resource: R): AccessDecision =
        if (rules.any { it.matches(subject, operation, resource) }) Granted else Denied(NoMatchingAllowRule(operation, resource::class))
}

/** Collects the `allow` rules of one policy. Rules only allow; anything no rule allows is denied. */
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

/**
 * Builds the policy for resources of type [R] (and its subtypes without their own policy), for subjects of type
 * [S]. Register it in a catalog with [AclCatalogBuilder.register].
 *
 * ```kotlin
 * val bookPolicy = aclPolicy<User, Book> {
 *     allow(Read, Write) { user, book -> user.id == book.userId }
 * }
 * ```
 */
public inline fun <S : Any, reified R : Any> aclPolicy(
    noinline block: AclPolicyBuilder<S, R>.() -> Unit,
): AclPolicy<S, R> = AclPolicyBuilder<S, R>().apply(block).build(R::class)
