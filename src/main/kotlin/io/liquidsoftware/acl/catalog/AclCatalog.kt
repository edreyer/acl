package io.liquidsoftware.acl.catalog

import io.liquidsoftware.acl.Operation
import io.liquidsoftware.acl.decision.AccessDecision
import io.liquidsoftware.acl.decision.AccessPartition
import io.liquidsoftware.acl.decision.BatchAccessDecision
import io.liquidsoftware.acl.policy.AclDsl
import io.liquidsoftware.acl.policy.AclPolicy
import io.liquidsoftware.acl.policy.AclPolicyBuilder
import io.liquidsoftware.acl.policy.aclPolicy

class AclCatalog internal constructor(
    private val engine: AclDecisionEngine,
) {
    fun <S : Any, R : Any> decide(subject: S, operation: Operation, resource: R): AccessDecision {
        return engine.decide(subject, operation, resource)
    }

    fun <S : Any, R : Any> can(subject: S, operation: Operation, resource: R): Boolean =
        engine.can(subject, operation, resource)

    fun <S : Any, R : Any> canRead(subject: S, resource: R): Boolean =
        can(subject, Operation.Read, resource)

    fun <S : Any, R : Any> canWrite(subject: S, resource: R): Boolean =
        can(subject, Operation.Write, resource)

    fun <S : Any, R : Any> canManage(subject: S, resource: R): Boolean =
        can(subject, Operation.Manage, resource)

    fun <S : Any, R : Any> decideAll(
        subject: S,
        operation: Operation,
        resources: Iterable<R>,
    ): BatchAccessDecision<R> {
        return engine.decideAll(subject, operation, resources)
    }

    fun <S : Any, R : Any> canAll(subject: S, operation: Operation, resources: Iterable<R>): Boolean =
        engine.canAll(subject, operation, resources)

    fun <S : Any, R : Any> canReadAll(subject: S, resources: Iterable<R>): Boolean =
        canAll(subject, Operation.Read, resources)

    fun <S : Any, R : Any> canWriteAll(subject: S, resources: Iterable<R>): Boolean =
        canAll(subject, Operation.Write, resources)

    fun <S : Any, R : Any> canManageAll(subject: S, resources: Iterable<R>): Boolean =
        canAll(subject, Operation.Manage, resources)

    fun <S : Any, R : Any> filterBy(subject: S, operation: Operation, resources: Iterable<R>): List<R> =
        engine.filterBy(subject, operation, resources)

    fun <S : Any, R : Any> filterReadableBy(subject: S, resources: Iterable<R>): List<R> =
        filterBy(subject, Operation.Read, resources)

    fun <S : Any, R : Any> filterWritableBy(subject: S, resources: Iterable<R>): List<R> =
        filterBy(subject, Operation.Write, resources)

    fun <S : Any, R : Any> filterManageableBy(subject: S, resources: Iterable<R>): List<R> =
        filterBy(subject, Operation.Manage, resources)

    fun <S : Any, R : Any> partitionBy(
        subject: S,
        operation: Operation,
        resources: Iterable<R>,
    ): AccessPartition<R> = engine.partitionBy(subject, operation, resources)

    fun <S : Any, R : Any> partitionReadableBy(subject: S, resources: Iterable<R>): AccessPartition<R> =
        partitionBy(subject, Operation.Read, resources)

    fun <S : Any, R : Any> partitionWritableBy(subject: S, resources: Iterable<R>): AccessPartition<R> =
        partitionBy(subject, Operation.Write, resources)

    fun <S : Any, R : Any> partitionManageableBy(subject: S, resources: Iterable<R>): AccessPartition<R> =
        partitionBy(subject, Operation.Manage, resources)
}

@AclDsl
class AclCatalogBuilder {
    private val registry = AclPolicyRegistry.Builder()

    fun <S : Any, R : Any> register(policy: AclPolicy<S, R>) {
        registry.register(policy)
    }

    inline fun <reified S : Any, reified R : Any> policy(
        noinline block: AclPolicyBuilder<S, R>.() -> Unit,
    ) {
        register(aclPolicy(block))
    }

    internal fun build(): AclCatalog = AclCatalog(AclDecisionEngine(registry.build()))
}

fun aclCatalog(block: AclCatalogBuilder.() -> Unit): AclCatalog =
    AclCatalogBuilder().apply(block).build()
