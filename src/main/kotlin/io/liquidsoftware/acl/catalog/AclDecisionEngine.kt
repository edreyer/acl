package io.liquidsoftware.acl.catalog

import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.decision.AccessDecision
import io.liquidsoftware.acl.decision.AccessDecision.Denied
import io.liquidsoftware.acl.decision.AccessPartition
import io.liquidsoftware.acl.decision.BatchAccessDecision
import io.liquidsoftware.acl.decision.ItemAccessDecision
import io.liquidsoftware.acl.decision.NoPolicyRegistered

internal class AclDecisionEngine(
    private val registry: AclPolicyRegistry,
) {
    fun <S : Any, R : Any> decide(subject: S, operation: Operation, resource: R): AccessDecision {
        val policy = registry.resolve(resource)
        return if (policy == null) {
            Denied(NoPolicyRegistered(resource::class))
        } else {
            policy.decide(subject, operation, resource)
        }
    }

    fun <S : Any, R : Any> can(subject: S, operation: Operation, resource: R): Boolean =
        decide(subject, operation, resource).granted

    fun <S : Any, R : Any> decideAll(
        subject: S,
        operation: Operation,
        resources: Iterable<R>,
    ): BatchAccessDecision<R> {
        val decisions = resources.map { resource ->
            ItemAccessDecision(
                resource = resource,
                decision = decide(subject, operation, resource),
            )
        }
        return BatchAccessDecision(decisions)
    }

    fun <S : Any, R : Any> canAll(subject: S, operation: Operation, resources: Iterable<R>): Boolean =
        decideAll(subject, operation, resources).allGranted

    fun <S : Any, R : Any> filterBy(subject: S, operation: Operation, resources: Iterable<R>): List<R> =
        decideAll(subject, operation, resources).allowed

    fun <S : Any, R : Any> partitionBy(
        subject: S,
        operation: Operation,
        resources: Iterable<R>,
    ): AccessPartition<R> = decideAll(subject, operation, resources).partition()
}
