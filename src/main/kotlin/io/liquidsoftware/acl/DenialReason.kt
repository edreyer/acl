package io.liquidsoftware.acl

import kotlin.reflect.KClass

/** Why an [AccessDecision.Denied] was denied. */
public sealed interface DenialReason {
    /** A human-readable description, suitable for logs. */
    public val message: String
}

/** The resource's policy has no rule that allows the operation for this subject and resource. */
public data object NoMatchingAllowRule : DenialReason {
    override val message: String = "No matching allow rule"

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
