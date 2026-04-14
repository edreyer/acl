package io.liquidsoftware.acl

internal data class User(val id: String, val isSystemAdmin: Boolean)
internal data class Book(val userId: String)
internal data class Invoice(val ownerId: String)
