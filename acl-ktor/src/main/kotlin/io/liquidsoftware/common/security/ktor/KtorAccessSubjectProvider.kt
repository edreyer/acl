package io.liquidsoftware.common.security.ktor

import io.ktor.server.application.ApplicationCall
import io.ktor.util.AttributeKey
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
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

  suspend fun hasPermission(call: ApplicationCall, acl: Acl, permission: Permission): Boolean =
    aclChecker.hasPermission(acl, currentSubject(call), permission)
}
