package io.liquidsoftware.acl

/**
 * Something a subject can do to a resource.
 *
 * [Read], [Write] and [Manage] are built in. Declare your own as objects:
 *
 * ```kotlin
 * data object Approve : Operation
 * ```
 *
 * A rule for an operation grants every operation it [covers]. By default an operation covers only itself;
 * [Manage] covers every operation, including custom ones.
 */
public interface Operation {
    /** Whether a rule that allows this operation also allows [requested]. */
    public fun covers(requested: Operation): Boolean = requested == this

    public data object Read : Operation

    public data object Write : Operation

    public data object Manage : Operation {
        override fun covers(requested: Operation): Boolean = true
    }
}
