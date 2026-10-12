package io.liquidsoftware.acl

import kotlin.test.Test
import kotlin.test.assertEquals

class DenialReasonTest {
    @Test
    fun denial_reasons_render_human_readable_messages() {
        assertEquals(
            "No matching allow rule",
            NoMatchingAllowRule.toString(),
        )

        assertEquals(
            "No policy registered for kotlin.String",
            NoPolicyRegistered(String::class).toString(),
        )

        assertEquals(
            "Ambiguous policies for kotlin.String: kotlin.CharSequence, kotlin.Comparable. " +
                "Register a policy for kotlin.String to resolve it.",
            AmbiguousPolicy(String::class, listOf(CharSequence::class, Comparable::class)).toString(),
        )

        assertEquals(
            "Denied(reason=No matching allow rule)",
            AccessDecision.Denied(NoMatchingAllowRule).toString(),
        )
    }
}
