package io.liquidsoftware.acl

public sealed interface AccessDecision {
    public val granted: Boolean

    public data object Granted : AccessDecision {
        override val granted: Boolean = true
    }

    public data class Denied(val reason: DenialReason) : AccessDecision {
        override val granted: Boolean = false
    }
}
