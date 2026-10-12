package io.liquidsoftware.acl

internal class AclRule<in S : Any, in R : Any>(
    private val operations: Set<Operation>,
    private val predicate: (S, R) -> Boolean,
) {
    fun matches(subject: S, operation: Operation, resource: R): Boolean =
        operations.any { it.covers(operation) } && predicate(subject, resource)
}
