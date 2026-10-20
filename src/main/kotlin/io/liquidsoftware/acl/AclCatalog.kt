package io.liquidsoftware.acl

/**
 * Answers whether a subject of type [S] may perform an operation on a resource.
 *
 * Resources are routed to the policy registered for their most specific type. A resource with no
 * matching policy is denied with [NoPolicyRegistered].
 *
 * A catalog is immutable once built and safe to share between threads. It caches the routing decision per resource
 * class. Rules run on the calling thread, and an exception a rule throws propagates out of the check.
 */
public class AclCatalog<S : Any> internal constructor(
    private val registry: AclPolicyRegistry<S>,
) {
    /** Decides whether [subject] may perform [operation] on [resource], with the reason when it may not. */
    public fun decide(subject: S, operation: Operation, resource: Any): AccessDecision =
        registry.decide(subject, operation, resource)

    /** Whether [subject] may perform [operation] on [resource]. Use [decide] to find out why not. */
    public fun can(subject: S, operation: Operation, resource: Any): Boolean =
        decide(subject, operation, resource).granted

    /** Whether [subject] may [Operation.Read] [resource]. */
    public fun canRead(subject: S, resource: Any): Boolean = can(subject, Operation.Read, resource)

    /** Whether [subject] may [Operation.Write] [resource]. */
    public fun canWrite(subject: S, resource: Any): Boolean = can(subject, Operation.Write, resource)

    /** Whether [subject] may [Operation.Manage] [resource]. */
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
    /** Decides whether [subject] may perform [operation] on [resource]. See [AclCatalog.decide]. */
    public fun decide(operation: Operation, resource: Any): AccessDecision =
        catalog.decide(subject, operation, resource)

    /** Whether [subject] may perform [operation] on [resource]. */
    public fun can(operation: Operation, resource: Any): Boolean = catalog.can(subject, operation, resource)

    /** Whether [subject] may [Operation.Read] [resource]. */
    public fun canRead(resource: Any): Boolean = catalog.canRead(subject, resource)

    /** Whether [subject] may [Operation.Write] [resource]. */
    public fun canWrite(resource: Any): Boolean = catalog.canWrite(subject, resource)

    /** Whether [subject] may [Operation.Manage] [resource]. */
    public fun canManage(resource: Any): Boolean = catalog.canManage(subject, resource)
}

/**
 * Collects the policies of a catalog. Registering two policies for one resource type, or a policy for `Any`,
 * throws while the catalog is built.
 */
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
