package io.liquidsoftware.acl

/** The result of an access check: [Granted], or [Denied] with the [DenialReason]. */
public sealed interface AccessDecision {
    /** Whether access was granted. */
    public val granted: Boolean

    /** A rule allowed the operation. */
    public data object Granted : AccessDecision {
        override val granted: Boolean = true
    }

    /** No rule allowed the operation, or the resource could not be routed to a policy. See [reason]. */
    public data class Denied(val reason: DenialReason) : AccessDecision {
        override val granted: Boolean = false
    }
}
