package io.liquidsoftware.common.security.acl.arrow

import arrow.core.raise.Raise
import arrow.core.raise.context.ensure
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.AccessDenied
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.Authorizer
import io.liquidsoftware.common.security.acl.AuthorizationError
import io.liquidsoftware.common.security.acl.DenialContext
import io.liquidsoftware.common.security.acl.Permission
import io.liquidsoftware.common.security.acl.SecuredResource

context(_: Raise<AuthorizationError>)
suspend fun AclChecker.ensurePermission(subject: AccessSubject, acl: Acl, permission: Permission) {
  ensure(hasPermission(acl, subject, permission)) {
    AccessDenied(
      permission = permission,
      context = DenialContext.Acl(
        resourceId = acl.resourceId,
        subjectId = subject.userId,
      ),
    )
  }
}

context(_: Raise<AuthorizationError>)
suspend fun AclChecker.ensureCanRead(subject: AccessSubject, acl: Acl) {
  ensurePermission(subject, acl, Permission.READ)
}

context(_: Raise<AuthorizationError>)
suspend fun AclChecker.ensureCanWrite(subject: AccessSubject, acl: Acl) {
  ensurePermission(subject, acl, Permission.WRITE)
}

context(_: Raise<AuthorizationError>)
suspend fun AclChecker.ensureCanManage(subject: AccessSubject, acl: Acl) {
  ensurePermission(subject, acl, Permission.MANAGE)
}

context(ac: AclChecker, _: Raise<AuthorizationError>)
suspend fun AccessSubject.ensureCanRead(acl: Acl) {
  ac.ensureCanRead(this, acl)
}

context(ac: AclChecker, _: Raise<AuthorizationError>)
suspend fun AccessSubject.ensureCanRead(resource: SecuredResource) {
  ensureCanRead(resource.acl())
}

context(ac: AclChecker, _: Raise<AuthorizationError>)
suspend fun AccessSubject.ensureCanWrite(acl: Acl) {
  ac.ensureCanWrite(this, acl)
}

context(ac: AclChecker, _: Raise<AuthorizationError>)
suspend fun AccessSubject.ensureCanWrite(resource: SecuredResource) {
  ensureCanWrite(resource.acl())
}

context(ac: AclChecker, _: Raise<AuthorizationError>)
suspend fun AccessSubject.ensureCanManage(acl: Acl) {
  ac.ensureCanManage(this, acl)
}

context(ac: AclChecker, _: Raise<AuthorizationError>)
suspend fun AccessSubject.ensureCanManage(resource: SecuredResource) {
  ensureCanManage(resource.acl())
}

context(_: Raise<AuthorizationError>)
suspend fun <S, R> Authorizer<S, R>.ensureHasAccess(subject: S, resource: R, permission: Permission) {
  ensure(hasAccess(subject, resource, permission)) {
    AccessDenied(permission = permission)
  }
}

context(_: Raise<AuthorizationError>)
suspend fun <S, R> Authorizer<S, R>.ensureCanRead(subject: S, resource: R) {
  ensureHasAccess(subject, resource, Permission.READ)
}

context(_: Raise<AuthorizationError>)
suspend fun <S, R> Authorizer<S, R>.ensureCanWrite(subject: S, resource: R) {
  ensureHasAccess(subject, resource, Permission.WRITE)
}

context(_: Raise<AuthorizationError>)
suspend fun <S, R> Authorizer<S, R>.ensureCanManage(subject: S, resource: R) {
  ensureHasAccess(subject, resource, Permission.MANAGE)
}

/**
 * Subject-first convenience form of [Authorizer.ensureHasAccess].
 *
 * If the subject type defines a member with the same name, Kotlin resolves to the member first.
 * Use `authorizer.ensureHasAccess(subject, resource, permission)` when you need the unambiguous form.
 */
context(authorizer: Authorizer<S, R>, _: Raise<AuthorizationError>)
suspend fun <S, R> S.ensureHasAccess(resource: R, permission: Permission) {
  authorizer.ensureHasAccess(this, resource, permission)
}

/**
 * Subject-first convenience form of [Authorizer.ensureCanRead].
 *
 * If the subject type defines a member with the same name, Kotlin resolves to the member first.
 * Use `authorizer.ensureCanRead(subject, resource)` when you need the unambiguous form.
 */
context(authorizer: Authorizer<S, R>, _: Raise<AuthorizationError>)
suspend fun <S, R> S.ensureCanRead(resource: R) {
  authorizer.ensureCanRead(this, resource)
}

/**
 * Subject-first convenience form of [Authorizer.ensureCanWrite].
 *
 * If the subject type defines a member with the same name, Kotlin resolves to the member first.
 * Use `authorizer.ensureCanWrite(subject, resource)` when you need the unambiguous form.
 */
context(authorizer: Authorizer<S, R>, _: Raise<AuthorizationError>)
suspend fun <S, R> S.ensureCanWrite(resource: R) {
  authorizer.ensureCanWrite(this, resource)
}

/**
 * Subject-first convenience form of [Authorizer.ensureCanManage].
 *
 * If the subject type defines a member with the same name, Kotlin resolves to the member first.
 * Use `authorizer.ensureCanManage(subject, resource)` when you need the unambiguous form.
 */
context(authorizer: Authorizer<S, R>, _: Raise<AuthorizationError>)
suspend fun <S, R> S.ensureCanManage(resource: R) {
  authorizer.ensureCanManage(this, resource)
}
