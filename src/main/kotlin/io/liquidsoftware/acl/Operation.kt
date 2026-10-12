package io.liquidsoftware.acl

public enum class Operation {
    Read,
    Write,
    Manage;

    public fun covers(requested: Operation): Boolean = when (this) {
        // Manage subsumes all operations, including itself.
        Manage -> true
        Read -> requested == Read
        Write -> requested == Write
    }
}
