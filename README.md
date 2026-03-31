# ACL

`acl` is a small Kotlin-first authorization library.

Its main goal is simple application code:

```kotlin
val canRead = documentAccess.canRead(user, document)
```

Instead of pushing every caller down to low-level ACL primitives, the library now supports a domain-facing `Authorizer<S, R>` API in `acl-core`. If you prefer Arrow, the same policy can be enforced with typed failures instead of exceptions, and denials can carry structured metadata.

## Installation

```xml
<dependency>
    <groupId>io.liquidsoftware</groupId>
    <artifactId>acl-core</artifactId>
    <version>0.3.0</version>
</dependency>
```

## Quick Start

Start by defining an authorizer for your domain types.

```kotlin
import io.liquidsoftware.common.security.acl.authorizer

/**
 * Application roles that influence document access.
 */
enum class Role {
  ADMIN,
  DOCUMENT_READER,
  DOCUMENT_EDITOR,
}

/**
 * The actor attempting to access a document.
 */
data class User(
  val id: String,
  val roles: Set<Role>,
)

/**
 * A document resource. The owner can fully manage it.
 */
data class Document(
  val id: String,
  val ownerId: String,
)

/**
 * Document authorization policy.
 *
 * - `canManage`: owners and admins can do anything
 * - `canWrite`: managers and editors can modify documents
 * - `canRead`: writers and readers can view documents
 */
val documentAccess = authorizer<User, Document> {
  canManage { user, document ->
    user.id == document.ownerId || Role.ADMIN in user.roles
  }

  canWrite { user, document ->
    canManage(user, document) || Role.DOCUMENT_EDITOR in user.roles
  }

  canRead { user, document ->
    canWrite(user, document) || Role.DOCUMENT_READER in user.roles
  }
}
```

Use it directly from application code:

```kotlin
val canRead = documentAccess.canRead(user, document)
val canWrite = documentAccess.canWrite(user, document)
val canManage = documentAccess.canManage(user, document)
```

This keeps the policy close to the domain model:

- `canManage` expresses the strongest rule
- `canWrite` can build on `canManage`
- `canRead` can build on `canWrite`

If a permission rule is not defined, access is denied by default.

## Arrow

Add `acl-arrow` if you want typed enforcement with Arrow `Raise`.

```kotlin
import arrow.core.Either
import arrow.core.raise.either
import io.liquidsoftware.common.security.acl.AuthorizationError
import io.liquidsoftware.common.security.acl.arrow.ensureCanWrite

suspend fun updateDocument(
  user: User,
  document: Document,
): Either<AuthorizationError, Unit> =
  with(documentAccess) {
    either {
      user.ensureCanWrite(document)
    }
  }
```

Permission denials are represented with:

```kotlin
AccessDenied(permission, context)
```

`Authorizer`-based checks can attach `DenialContext.Metadata(...)` when you want richer denial details.
Low-level `AclChecker`-based checks return `AccessDenied(permission, DenialContext.Acl(resourceId, subjectId))`.
If you need app-specific translation, inspect `AccessDenied.context` and map it in your application layer.

Equivalent explicit form:

```kotlin
either<AuthorizationError, Unit> {
  documentAccess.ensureCanWrite(user, document)
}
```

## Optional App-Layer Sugar

If you want `user.canRead(document)`, keep that as a tiny application-layer extension:

```kotlin
import io.liquidsoftware.common.security.acl.Authorizer

context(access: Authorizer<User, Document>)
suspend fun User.canRead(document: Document): Boolean =
  access.canRead(this, document)

context(access: Authorizer<User, Document>)
suspend fun User.canWrite(document: Document): Boolean =
  access.canWrite(this, document)

context(access: Authorizer<User, Document>)
suspend fun User.canManage(document: Document): Boolean =
  access.canManage(this, document)
```

Usage:

```kotlin
with(documentAccess) {
  val canRead = user.canRead(document)
}
```

This keeps your domain types free of framework or library interfaces while still reading naturally.

## Modules

### `acl-core`

Pure Kotlin authorization core.

Use this if you want:

- `Authorizer<S, R>`
- `authorizer { ... }`
- `canRead`, `canWrite`, `canManage`, and `hasAccess`
- low-level ACL primitives when you need them

Key types:

- `Authorizer<S, R>`
- `RuleScope<S, R>`
- `AccessDenied`
- `AuthorizationError`
- `DenialContext`
- `Acl`
- `AclChecker`
- `AccessSubject`

### `acl-arrow`

Arrow integration for both API layers.

Use this if you want:

- `Authorizer.ensureCanRead(...)`
- `Authorizer.ensureCanWrite(...)`
- `Authorizer.ensureCanManage(...)`
- `Authorizer.ensureHasAccess(...)`
- low-level `AclChecker.ensureCanRead(...)` and related helpers

### `acl-spring-security`

Spring Security integration for resolving the current subject as an `AccessSubject`.

Use this if you want:

- `SpringSecurityAccessSubjectProvider`
- `currentSubject()`
- explicit wiring via `SpringSecurityAccessSubjectProvider(...)`

### `acl-spring-security-arrow`

Bridge module for Spring Security plus Arrow.

Use this if you want:

- `SpringSecurityAclChecker`
- current-user ACL checks like `ensureCanRead(acl)`
- current-user authorizer enforcement like `ensureCanRead(resource, authorizer)`
- current-user `Raise<AuthorizationError>` checks against explicit ACL data
- optional `denialContext` callbacks for structured denial metadata
- explicit wiring via `SpringSecurityAclChecker(...)`

### `acl-ktor`

Ktor integration for resolving the current subject on `ApplicationCall`.

Use this if you want:

- `AclKtor`
- `ApplicationCall.currentSubject()`
- current-call authorizer checks like `call.canRead(resource, authorizer)`
- `ApplicationCall.hasPermission(...)`
- `ApplicationCall.canRead(...)`
- `ApplicationCall.canWrite(...)`
- `ApplicationCall.canManage(...)`

## Framework Examples

### Spring Security

`acl-spring-security` resolves the current subject and leaves authorization checks to the Spring checker.

The integration types are plain Kotlin classes, so you can wire them explicitly in your own configuration.

```kotlin
@Component
class AppointmentAccessService(
  private val accessSubjects: SpringSecurityAccessSubjectProvider,
) {
  fun currentSubject(): AccessSubject =
    accessSubjects.currentSubject()
}
```

### Spring Security With Arrow

```kotlin
import arrow.core.raise.Raise
import io.liquidsoftware.common.security.acl.AuthorizationError

@Component
class AppointmentPersistenceAdapter(
  private val acl: SpringSecurityAclChecker,
  private val appointmentAccess: Authorizer<AccessSubject, Appointment>,
) {
  context(_: Raise<AuthorizationError>)
  suspend fun ensureReadable(appointment: Appointment) {
    acl.ensureCanRead(appointment, appointmentAccess)
  }
}
```

### Ktor

`acl-ktor` can also evaluate authorizers against the current call subject.

```kotlin
authenticate {
  get("/documents/{id}") {
    val document = loadDocument(call.parameters["id"]!!)

    if (!call.canRead(document, documentAccess)) {
      call.respond(HttpStatusCode.Forbidden)
      return@get
    }

    call.respond(document)
  }
}
```

## Advanced: Explicit ACL Data

If your application already stores or constructs explicit ACL data, the lower-level engine is still available.

These permission checks are synchronous because they operate on in-memory ACL data.

```kotlin
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.Permission
import io.liquidsoftware.common.security.acl.acl

val subject = AccessSubject(
  userId = "u_123",
  roles = setOf("ROLE_USER"),
)

val documentAcl = acl("document-42") {
  manager("u_owner")
  writer("u_editor")
  reader("u_auditor")
}

val checker = AclChecker()

val allowed = checker.hasPermission(
  subject = subject,
  acl = documentAcl,
  permission = Permission.READ,
)
```

Low-level denials use the same `AccessDenied` type, but with ACL-specific context:

```kotlin
AccessDenied(
  permission = Permission.READ,
  context = DenialContext.Acl(
    resourceId = "document-42",
    subjectId = "u_123",
  ),
)
```

## Design Notes

- `acl-core` stays framework-neutral
- Arrow is optional
- Spring Security is optional
- current-user lookup belongs in integration modules, not in the core
- authorization denial is treated as data, not as an exception by default
