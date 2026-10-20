package io.liquidsoftware.acl

import kotlin.reflect.KClass

/** Why an [AccessDecision.Denied] was denied. */
public sealed interface DenialReason {
    /** A human-readable description, suitable for logs. */
    public val message: String
}

/**
 * The resource's policy has no rule that allows [operation] for this subject and resource. [resourceType] is the
 * resource's runtime class, which may be a subtype of the type the policy was registered for.
 */
public data class NoMatchingAllowRule(
    val operation: Operation,
    val resourceType: KClass<*>,
) : DenialReason {
    override val message: String = "No rule allows $operation on ${resourceType.displayName()}"

    override fun toString(): String = message
}

/**
 * No policy is registered for [resourceType] or any of its supertypes. This usually means a policy is missing from
 * the catalog rather than an intended denial.
 */
public data class NoPolicyRegistered(
    val resourceType: KClass<*>,
) : DenialReason {
    override val message: String = "No policy registered for ${resourceType.displayName()}"

    override fun toString(): String = message
}

/**
 * The resource matches policies for several [candidates] and none of them is a subtype of all the others,
 * for example two interfaces the resource implements. Register a policy for [resourceType] to resolve it.
 */
public data class AmbiguousPolicy(
    val resourceType: KClass<*>,
    val candidates: List<KClass<*>>,
) : DenialReason {
    override val message: String =
        "Ambiguous policies for ${resourceType.displayName()}: ${candidates.joinToString { it.displayName() }}. " +
            "Register a policy for ${resourceType.displayName()} to resolve it."

    override fun toString(): String = message
}
