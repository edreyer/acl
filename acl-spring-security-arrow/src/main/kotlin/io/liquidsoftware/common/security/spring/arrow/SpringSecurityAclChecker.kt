package io.liquidsoftware.common.security.spring.arrow

import arrow.core.raise.Raise
import arrow.core.raise.context.ensure
import io.liquidsoftware.common.security.acl.AccessDenied
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.DenialContext
import io.liquidsoftware.common.security.acl.Authorizer
import io.liquidsoftware.common.security.acl.AuthorizationError
import io.liquidsoftware.common.security.acl.Permission
import io.liquidsoftware.common.security.acl.arrow.ensureHasAccess
import io.liquidsoftware.common.security.acl.arrow.ensureCanManage
import io.liquidsoftware.common.security.acl.arrow.ensureCanRead
import io.liquidsoftware.common.security.acl.arrow.ensureCanWrite
import io.liquidsoftware.common.security.spring.SpringSecurityAccessSubjectProvider

class SpringSecurityAclChecker(
  private val accessSubjectProvider: SpringSecurityAccessSubjectProvider,
  private val aclChecker: AclChecker,
) {
  /**
   * Ensures the current subject can read the given ACL.
   *
   * This is a thin wrapper over shared ACL check logic so the public API keeps
   * named entry points for the common permissions.
   */
  context(_: Raise<AuthorizationError>)
  fun ensureCanRead(acl: Acl) {
    ensureAclPermission(acl, Permission.READ)
  }

  /**
   * Ensures the current subject can write the given ACL.
   *
   * This is a thin wrapper over shared ACL check logic so the public API keeps
   * named entry points for the common permissions.
   */
  context(_: Raise<AuthorizationError>)
  fun ensureCanWrite(acl: Acl) {
    ensureAclPermission(acl, Permission.WRITE)
  }

  /**
   * Ensures the current subject can manage the given ACL.
   *
   * This is a thin wrapper over shared ACL check logic so the public API keeps
   * named entry points for the common permissions.
   */
  context(_: Raise<AuthorizationError>)
  fun ensureCanManage(acl: Acl) {
    ensureAclPermission(acl, Permission.MANAGE)
  }

  context(_: Raise<AuthorizationError>)
  suspend fun <R> ensureHasAccess(
    resource: R,
    permission: Permission,
    authorizer: Authorizer<AccessSubject, R>,
    denialContext: (AccessSubject, R, Permission) -> DenialContext = { _, _, _ -> DenialContext.Unknown },
  ) {
    val subject = accessSubjectProvider.currentSubject()
    authorizer.ensureHasAccess(subject, resource, permission, denialContext)
  }

  context(_: Raise<AuthorizationError>)
  suspend fun <R> ensureCanRead(
    resource: R,
    authorizer: Authorizer<AccessSubject, R>,
    denialContext: (AccessSubject, R, Permission) -> DenialContext = { _, _, _ -> DenialContext.Unknown },
  ) {
    val subject = accessSubjectProvider.currentSubject()
    authorizer.ensureCanRead(subject, resource, denialContext)
  }

  context(_: Raise<AuthorizationError>)
  suspend fun <R> ensureCanWrite(
    resource: R,
    authorizer: Authorizer<AccessSubject, R>,
    denialContext: (AccessSubject, R, Permission) -> DenialContext = { _, _, _ -> DenialContext.Unknown },
  ) {
    val subject = accessSubjectProvider.currentSubject()
    authorizer.ensureCanWrite(subject, resource, denialContext)
  }

  context(_: Raise<AuthorizationError>)
  suspend fun <R> ensureCanManage(
    resource: R,
    authorizer: Authorizer<AccessSubject, R>,
    denialContext: (AccessSubject, R, Permission) -> DenialContext = { _, _, _ -> DenialContext.Unknown },
  ) {
    val subject = accessSubjectProvider.currentSubject()
    authorizer.ensureCanManage(subject, resource, denialContext)
  }

  /**
   * Shared ACL evaluation used by the public permission-specific wrappers.
   */
  context(_: Raise<AuthorizationError>)
  private fun ensureAclPermission(acl: Acl, permission: Permission) {
    val subject = accessSubjectProvider.currentSubject()
    ensure(aclChecker.hasPermission(subject, acl, permission)) {
      AccessDenied(
        permission = permission,
        context = DenialContext.Acl(
          resourceId = acl.resourceId,
          subjectId = subject.userId,
        ),
      )
    }
  }
}
