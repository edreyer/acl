package io.liquidsoftware.common.security.ktor

import io.ktor.server.application.ApplicationCall
import io.ktor.util.AttributeKey
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.Authorizer
import io.liquidsoftware.common.security.acl.Permission

private val CurrentAccessSubjectKey = AttributeKey<AccessSubject>("acl.current-subject")

class KtorAccessSubjectProvider(
  private val resolver: ApplicationCallAccessSubjectResolver,
  private val aclChecker: AclChecker = AclChecker(),
) {

  fun currentSubject(call: ApplicationCall): AccessSubject {
    if (call.attributes.contains(CurrentAccessSubjectKey)) {
      return call.attributes[CurrentAccessSubjectKey]
    }

    return resolver.resolve(call).also { call.attributes.put(CurrentAccessSubjectKey, it) }
  }

  fun hasPermission(call: ApplicationCall, acl: Acl, permission: Permission): Boolean =
    aclChecker.hasPermission(currentSubject(call), acl, permission)

  /**
   * Evaluates a domain-facing [Authorizer] against the current call subject.
   *
   * This intentionally bypasses [AclChecker]. `hasPermission(...)` is the
   * low-level ACL-engine path for explicit [Acl] data, while `hasAccess(...)`
   * is the authorizer path for rule-based policies over domain resources.
   */
  suspend fun <R> hasAccess(
    call: ApplicationCall,
    resource: R,
    permission: Permission,
    authorizer: Authorizer<AccessSubject, R>,
  ): Boolean = authorizer.hasAccess(currentSubject(call), resource, permission)
}
