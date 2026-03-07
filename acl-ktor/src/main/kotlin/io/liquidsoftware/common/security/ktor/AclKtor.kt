package io.liquidsoftware.common.security.ktor

import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.createApplicationPlugin
import io.ktor.util.AttributeKey
import io.liquidsoftware.common.security.acl.ANONYMOUS_SUBJECT_ID
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.Permission
import io.liquidsoftware.common.security.acl.SecuredResource

private val AccessSubjectProviderKey =
  AttributeKey<KtorAccessSubjectProvider>("acl.access-subject-provider")

class AclKtorConfiguration {
  var resolver: ApplicationCallAccessSubjectResolver = ApplicationCallAccessSubjectResolver {
    AccessSubject(
      userId = ANONYMOUS_SUBJECT_ID,
      roles = emptySet(),
    )
  }
  var aclChecker: AclChecker = AclChecker()
}

val AclKtor = createApplicationPlugin(
  name = "AclKtor",
  createConfiguration = ::AclKtorConfiguration,
) {
  val accessSubjectProvider = KtorAccessSubjectProvider(
    resolver = pluginConfig.resolver,
    aclChecker = pluginConfig.aclChecker,
  )

  application.attributes.put(AccessSubjectProviderKey, accessSubjectProvider)
}

fun Application.aclAccessSubjectProvider(): KtorAccessSubjectProvider =
  if (attributes.contains(AccessSubjectProviderKey)) {
    attributes[AccessSubjectProviderKey]
  } else {
    error("AclKtor plugin is not installed")
  }

fun ApplicationCall.currentSubject(): AccessSubject =
  application.aclAccessSubjectProvider().currentSubject(this)

suspend fun ApplicationCall.hasPermission(acl: Acl, permission: Permission): Boolean =
  application.aclAccessSubjectProvider().hasPermission(this, acl, permission)

suspend fun ApplicationCall.hasPermission(resource: SecuredResource, permission: Permission): Boolean =
  hasPermission(resource.acl(), permission)

suspend fun ApplicationCall.canRead(acl: Acl): Boolean =
  hasPermission(acl, Permission.READ)

suspend fun ApplicationCall.canRead(resource: SecuredResource): Boolean =
  hasPermission(resource, Permission.READ)

suspend fun ApplicationCall.canWrite(acl: Acl): Boolean =
  hasPermission(acl, Permission.WRITE)

suspend fun ApplicationCall.canWrite(resource: SecuredResource): Boolean =
  hasPermission(resource, Permission.WRITE)

suspend fun ApplicationCall.canManage(acl: Acl): Boolean =
  hasPermission(acl, Permission.MANAGE)

suspend fun ApplicationCall.canManage(resource: SecuredResource): Boolean =
  hasPermission(resource, Permission.MANAGE)
