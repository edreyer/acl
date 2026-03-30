package io.liquidsoftware.common.security.spring.arrow

import arrow.core.raise.Raise
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.Authorizer
import io.liquidsoftware.common.security.acl.AuthorizationError
import io.liquidsoftware.common.security.acl.Permission
import io.liquidsoftware.common.security.acl.arrow.ensureHasAccess
import io.liquidsoftware.common.security.acl.arrow.ensureCanManage
import io.liquidsoftware.common.security.acl.arrow.ensureCanRead
import io.liquidsoftware.common.security.acl.arrow.ensureCanWrite
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.spring.SpringSecurityAccessSubjectProvider
import org.springframework.stereotype.Component

@Component
class SpringSecurityAclChecker(
  private val accessSubjectProvider: SpringSecurityAccessSubjectProvider,
) {
  private val aclChecker = AclChecker()

  context(_: Raise<AuthorizationError>)
  suspend fun ensureCanRead(acl: Acl) {
    aclChecker.ensureCanRead(accessSubjectProvider.currentSubject(), acl)
  }

  context(_: Raise<AuthorizationError>)
  suspend fun ensureCanWrite(acl: Acl) {
    aclChecker.ensureCanWrite(accessSubjectProvider.currentSubject(), acl)
  }

  context(_: Raise<AuthorizationError>)
  suspend fun ensureCanManage(acl: Acl) {
    aclChecker.ensureCanManage(accessSubjectProvider.currentSubject(), acl)
  }

  context(_: Raise<AuthorizationError>)
  suspend fun <R> ensureHasAccess(
    resource: R,
    permission: Permission,
    authorizer: Authorizer<AccessSubject, R>,
  ) {
    authorizer.ensureHasAccess(accessSubjectProvider.currentSubject(), resource, permission)
  }

  context(_: Raise<AuthorizationError>)
  suspend fun <R> ensureCanRead(
    resource: R,
    authorizer: Authorizer<AccessSubject, R>,
  ) {
    authorizer.ensureCanRead(accessSubjectProvider.currentSubject(), resource)
  }

  context(_: Raise<AuthorizationError>)
  suspend fun <R> ensureCanWrite(
    resource: R,
    authorizer: Authorizer<AccessSubject, R>,
  ) {
    authorizer.ensureCanWrite(accessSubjectProvider.currentSubject(), resource)
  }

  context(_: Raise<AuthorizationError>)
  suspend fun <R> ensureCanManage(
    resource: R,
    authorizer: Authorizer<AccessSubject, R>,
  ) {
    authorizer.ensureCanManage(accessSubjectProvider.currentSubject(), resource)
  }
}
