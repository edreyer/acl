package io.liquidsoftware.acl

import io.liquidsoftware.acl.decision.AccessDecision
import io.liquidsoftware.acl.decision.NoMatchingAllowRule
import io.liquidsoftware.acl.decision.NoPolicyRegistered
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
            "Denied(reason=No matching allow rule)",
            AccessDecision.Denied(NoMatchingAllowRule).toString(),
        )
    }
}
