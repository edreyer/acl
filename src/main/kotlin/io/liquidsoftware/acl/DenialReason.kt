package io.liquidsoftware.acl

import kotlin.reflect.KClass

public sealed interface DenialReason {
    public val message: String
}

public data object NoMatchingAllowRule : DenialReason {
    override val message: String = "No matching allow rule"

    override fun toString(): String = message
}

public data class NoPolicyRegistered(
    val resourceType: KClass<*>,
) : DenialReason {
    override val message: String = "No policy registered for ${resourceType.qualifiedName ?: resourceType.simpleName ?: "unknown"}"

    override fun toString(): String = message
}
