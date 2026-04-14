package io.liquidsoftware.acl.policy

import io.liquidsoftware.acl.Operation

sealed interface AclRule<S : Any, R : Any> {
    val operation: Operation

    fun matches(subject: S, resource: R): Boolean

    class SubjectOnly<S : Any, R : Any>(
        override val operation: Operation,
        val predicate: (S) -> Boolean,
    ) : AclRule<S, R> {
        override fun matches(subject: S, resource: R): Boolean = predicate(subject)
    }

    class SubjectAndResource<S : Any, R : Any>(
        override val operation: Operation,
        val predicate: (S, R) -> Boolean,
    ) : AclRule<S, R> {
        override fun matches(subject: S, resource: R): Boolean = predicate(subject, resource)
    }
}
