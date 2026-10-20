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
 * A rule for an operation grants every operation it [covers]. By default an operation covers only itself,
 * compared with `==`, so a custom operation must be an object or have value equality (a data class). A plain
 * class instance only matches itself, so checks with a new instance are denied.
 *
 * [covers] is not transitive: if `Super` covers `Edit` and `Edit` covers [Read], a rule for `Super` still does not
 * grant [Read] unless `Super.covers(Read)` is true itself.
 *
 * [Manage] covers only the built-in operations. A custom operation is granted only by rules that name it
 * (for example `allow(Manage, Approve) { ... }`) or by an operation that overrides [covers] to include it.
 */
public interface Operation {
    /** Whether a rule that allows this operation also allows [requested]. */
    public fun covers(requested: Operation): Boolean = requested == this

    /** Read access. Covers only itself. */
    public data object Read : Operation

    /** Write access. Covers only itself. */
    public data object Write : Operation

    /** Covers [Read], [Write] and [Manage]. Custom operations must be granted by name. */
    public data object Manage : Operation {
        override fun covers(requested: Operation): Boolean = requested == Read || requested == Write || requested == Manage
    }
}
