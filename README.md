# ACL

`acl` is a small Kotlin-first access control library for applications that want authorization to stay explicit, typed, and close to the domain model.

It exists to solve a common problem in backend systems: authorization logic often becomes scattered across controllers, services, framework annotations, and exception handlers. Over time that usually turns into stringly checks, duplicated policy logic, and code paths where "not authorized" is treated as an exceptional condition even though it is a normal business outcome.

This project takes a different approach:

- model resources, subjects, roles, and permissions explicitly
- keep the core policy engine framework-neutral
- support functional Kotlin code with Arrow, but do not require Arrow
- support Spring Security, but do not require Spring
- keep "permission denied" as data instead of making exceptions the default

The current design is intentionally small. It is meant to be understandable, embeddable, and easy to integrate into a modular monolith or a service-based system.

## Why It Exists

This library exists to provide a clean middle ground between:

- hand-rolled ACL code scattered through an application
- heavy policy engines or infrastructure that are too large for the problem
- framework-specific authorization APIs that are hard to reuse outside one stack

The goals are:

- explicit authorization models
- type-safe subjects and permissions
- composable permission checks
- optional integrations for Arrow and Spring Security
- a clean path to OSS extraction and reuse

## Installation

The published coordinates use the `io.liquidsoftware` group id.

Example:

```xml
<dependency>
    <groupId>io.liquidsoftware</groupId>
    <artifactId>acl-core</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Modules

The project is split into five modules so users can adopt only the layers they want.

### `acl-core`

Pure Kotlin authorization core.

Contains:

- `Acl`
- `AclRole`
- `Permission`
- `AccessSubject`
- `AuthorizationError`
- `PermissionDenied`
- `SecuredResource`
- `AclChecker`
- ACL builder DSL via `acl(resourceId) { ... }`

No Arrow. No Spring. No current-user lookup.

This is the policy engine and model layer.

### `acl-arrow`

Arrow integration for the core.

Contains:

- `Raise<AuthorizationError>`-based enforcement helpers
- `ensurePermission(...)`
- `ensureCanRead(...)`
- `ensureCanWrite(...)`
- `ensureCanManage(...)`
- `AccessSubject` extension helpers
- `SecuredResource` extension overloads

This module exists so Arrow users get a natural `Raise` API without forcing Arrow on everyone else.

### `acl-spring-security`

Spring Security integration without Arrow.

Contains:

- current-subject resolution from `SecurityContextHolder`
- `AuthenticationAccessSubjectResolver`
- `SpringSecurityAccessSubjectProvider`

This module exists for users who want to integrate ACL with Spring Security but prefer boolean/value-based APIs over Arrow.

### `acl-spring-security-arrow`

Bridge module for users who want both Spring Security and Arrow.

Contains:

- `SpringSecurityAclChecker`
- current-subject `Raise`-based permission checks

This module is intentionally separate so Spring users are not forced to take Arrow, and Arrow users are not forced to take Spring.

### `acl-ktor`

Ktor integration without Arrow.

Contains:

- Ktor `ApplicationCall` access-subject resolution
- `AclKtor` plugin wiring
- `ApplicationCall.currentSubject()`
- `ApplicationCall.hasPermission(...)`
- `ApplicationCall.canRead(...)`
- `ApplicationCall.canWrite(...)`
- `ApplicationCall.canManage(...)`

This module exists for Ktor applications that want framework-native access to the current subject without pulling in Spring Security concepts.

## Core Concepts

### Subject

A subject is the actor attempting to do something.

```kotlin
val subject = AccessSubject(
  userId = "u_123",
  roles = setOf("ROLE_USER")
)
```

### Resource ACL

An ACL describes who can do what on a specific resource.

```kotlin
val appointmentAcl = acl("appointment-123") {
  manager("u_owner")
  writer("u_assistant")
  reader("u_auditor")
  anonymousReader()
}
```

### Permission Evaluation

The core checker answers a simple question: can this subject perform this permission on this resource?

```kotlin
val checker = AclChecker()

val allowed = checker.hasPermission(
  acl = appointmentAcl,
  subject = subject,
  permission = Permission.READ
)
```

## Examples

### Example 1: Core Only

```kotlin
val acl = acl("vehicle-42") {
  manager("u_owner")
  reader("u_service-advisor")
}

val checker = AclChecker()

val subject = AccessSubject(
  userId = "u_service-advisor",
  roles = emptySet()
)

val canRead = checker.hasPermission(acl, subject, Permission.READ)
val canManage = checker.hasPermission(acl, subject, Permission.MANAGE)
```

### Example 2: Core With `SecuredResource`

```kotlin
data class Appointment(
  val id: String,
  private val appointmentAcl: Acl,
) : SecuredResource {
  override fun acl(): Acl = appointmentAcl
}
```

This keeps the resource authorization data close to the domain model without forcing the rest of the model to know anything about Spring or Arrow.

### Example 3: Arrow Integration

```kotlin
import arrow.core.Either
import arrow.core.raise.either
import io.liquidsoftware.common.security.acl.AuthorizationError
import io.liquidsoftware.common.security.acl.arrow.ensureCanWrite

suspend fun updateAppointment(
  checker: AclChecker,
  subject: AccessSubject,
  acl: Acl,
): Either<AuthorizationError, Unit> =
  either {
    checker.ensureCanWrite(subject, acl)
  }
```

This keeps authorization denial as a typed value rather than throwing exceptions for expected failures.

### Example 4: Spring Security Without Arrow

```kotlin
@Component
class AppointmentAccessService(
  private val accessSubjects: SpringSecurityAccessSubjectProvider,
) {
  suspend fun canCurrentUserRead(acl: Acl): Boolean =
    accessSubjects.hasPermission(acl, Permission.READ)
}
```

### Example 5: Spring Security With Arrow

```kotlin
import arrow.core.raise.Raise
import io.liquidsoftware.common.security.acl.AuthorizationError

@Component
class AppointmentPersistenceAdapter(
  private val acl: SpringSecurityAclChecker,
) {
  context(_: Raise<AuthorizationError>)
  suspend fun ensureReadable(resourceAcl: Acl) {
    acl.ensureCanRead(resourceAcl)
  }
}
```

This is the most ergonomic option for applications already using both Spring Security and Arrow.

## Design Principles

- `acl-core` stays free of frameworks and Arrow.
- Authorization denial is expected data, not exceptional control flow.
- Current-subject resolution belongs in adapters, not in the core policy engine.
- Spring integrations should feel natural to Spring users without forcing functional styles.
- Arrow integrations should feel natural to Arrow users without leaking Arrow into the core.
- Public APIs should remain small, readable, and Kotlin-idiomatic.

## What This Project Is Not

This project is not trying to be:

- a full policy language
- a distributed authorization server
- a database-backed ACL subsystem
- a replacement for every authorization use case

It is a focused library for applications that want explicit, embeddable ACL-based authorization with optional integration layers.

## Likely Future Scope

The likely evolution of the project is:

- stabilize these modules as a standalone OSS project
- publish them independently
- consider additional integrations later where they preserve the small core API surface
