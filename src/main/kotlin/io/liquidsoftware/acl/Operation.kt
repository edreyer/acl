package io.liquidsoftware.acl

enum class Operation {
    Read,
    Write,
    Manage;

    fun covers(requested: Operation): Boolean = when (this) {
        // Manage subsumes all operations, including itself.
        Manage -> true
        Read -> requested == Read
        Write -> requested == Write
    }
}
