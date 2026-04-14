package io.liquidsoftware.acl.decision

import kotlin.reflect.KClass

sealed interface DenialReason {
    val message: String
}

data object NoMatchingAllowRule : DenialReason {
    override val message: String = "No matching allow rule"

    override fun toString(): String = message
}

data class NoPolicyRegistered(
    val resourceType: KClass<*>,
) : DenialReason {
    override val message: String = "No policy registered for ${resourceType.qualifiedName ?: resourceType.simpleName ?: "unknown"}"

    override fun toString(): String = message
}
