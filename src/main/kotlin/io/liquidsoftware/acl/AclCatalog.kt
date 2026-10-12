package io.liquidsoftware.acl

/**
 * Answers whether a subject of type [S] may perform an operation on a resource.
 *
 * Resources are routed to the policy registered for their most specific type. A resource with no
 * matching policy is denied with [NoPolicyRegistered].
 */
public class AclCatalog<S : Any> internal constructor(
    private val registry: AclPolicyRegistry<S>,
) {
    public fun decide(subject: S, operation: Operation, resource: Any): AccessDecision =
        registry.decide(subject, operation, resource)

    public fun can(subject: S, operation: Operation, resource: Any): Boolean =
        decide(subject, operation, resource).granted

    public fun canRead(subject: S, resource: Any): Boolean = can(subject, Operation.Read, resource)

    public fun canWrite(subject: S, resource: Any): Boolean = can(subject, Operation.Write, resource)

    public fun canManage(subject: S, resource: Any): Boolean = can(subject, Operation.Manage, resource)

    /**
     * Binds [subject] so repeated checks don't have to pass it. The checks are plain functions, so they
     * compose with collections: `books.filter(access::canRead)`.
     */
    public fun forSubject(subject: S): SubjectAccess<S> = SubjectAccess(this, subject)
}

/** Access checks for one subject against an [AclCatalog]. Create with [AclCatalog.forSubject]. */
public class SubjectAccess<S : Any> internal constructor(
    private val catalog: AclCatalog<S>,
    public val subject: S,
) {
    public fun decide(operation: Operation, resource: Any): AccessDecision =
        catalog.decide(subject, operation, resource)

    public fun can(operation: Operation, resource: Any): Boolean = catalog.can(subject, operation, resource)

    public fun canRead(resource: Any): Boolean = catalog.canRead(subject, resource)

    public fun canWrite(resource: Any): Boolean = catalog.canWrite(subject, resource)

    public fun canManage(resource: Any): Boolean = catalog.canManage(subject, resource)
}

@AclDsl
public class AclCatalogBuilder<S : Any> internal constructor() {
    private val registry = AclPolicyRegistry.Builder<S>()

    /** Registers a policy built separately with [aclPolicy]. */
    public fun register(policy: AclPolicy<S, *>) {
        registry.register(policy)
    }

    /** Declares and registers the policy for resource type [R]. */
    public inline fun <reified R : Any> policy(noinline block: AclPolicyBuilder<S, R>.() -> Unit) {
        register(aclPolicy(block))
    }

    internal fun build(): AclCatalog<S> = AclCatalog(registry.build())
}

/** Builds a catalog of policies for subjects of type [S]. */
public fun <S : Any> aclCatalog(block: AclCatalogBuilder<S>.() -> Unit): AclCatalog<S> =
    AclCatalogBuilder<S>().apply(block).build()
