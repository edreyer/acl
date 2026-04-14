package io.liquidsoftware.acl.decision

sealed interface AccessDecision {
    val granted: Boolean

    data object Granted : AccessDecision {
        override val granted: Boolean = true
    }

    data class Denied(val reason: DenialReason) : AccessDecision {
        override val granted: Boolean = false
    }
}

data class ItemAccessDecision<R>(
    val resource: R,
    val decision: AccessDecision,
) {
    val granted: Boolean
        get() = decision.granted
}

data class AccessPartition<R>(
    val allowed: List<R>,
    val denied: List<R>,
) {
    val allGranted: Boolean
        get() = denied.isEmpty()
}

data class BatchAccessDecision<R>(
    val decisions: List<ItemAccessDecision<R>>,
) {
    val allGranted: Boolean
        get() = decisions.all { it.granted }

    val allowed: List<R>
        get() = decisions.filter { it.granted }.map { it.resource }

    val denied: List<R>
        get() = decisions.filterNot { it.granted }.map { it.resource }

    fun partition(): AccessPartition<R> {
        val (allowedDecisions, deniedDecisions) = decisions.partition { it.granted }
        return AccessPartition(
            allowed = allowedDecisions.map { it.resource },
            denied = deniedDecisions.map { it.resource },
        )
    }
}
