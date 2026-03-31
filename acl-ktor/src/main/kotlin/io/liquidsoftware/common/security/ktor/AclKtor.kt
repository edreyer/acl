package io.liquidsoftware.common.security.ktor

import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.createApplicationPlugin
import io.ktor.util.AttributeKey
import io.liquidsoftware.common.security.acl.ANONYMOUS_SUBJECT_ID
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.Authorizer
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

fun ApplicationCall.hasPermission(acl: Acl, permission: Permission): Boolean =
  application.aclAccessSubjectProvider().hasPermission(this, acl, permission)

/**
 * Evaluates an [Authorizer] against the current call subject.
 *
 * This is the domain-facing policy path. For explicit [Acl] checks, use
 * [hasPermission].
 */
suspend fun <R> ApplicationCall.hasAccess(
  resource: R,
  permission: Permission,
  authorizer: Authorizer<AccessSubject, R>,
): Boolean = application.aclAccessSubjectProvider().hasAccess(this, resource, permission, authorizer)

fun ApplicationCall.hasPermission(resource: SecuredResource, permission: Permission): Boolean =
  hasPermission(resource.acl(), permission)

fun ApplicationCall.canRead(acl: Acl): Boolean =
  hasPermission(acl, Permission.READ)

fun ApplicationCall.canRead(resource: SecuredResource): Boolean =
  hasPermission(resource, Permission.READ)

/**
 * Domain-facing convenience form of [hasAccess] for [Permission.READ].
 */
suspend fun <R> ApplicationCall.canRead(resource: R, authorizer: Authorizer<AccessSubject, R>): Boolean =
  hasAccess(resource, Permission.READ, authorizer)

fun ApplicationCall.canWrite(acl: Acl): Boolean =
  hasPermission(acl, Permission.WRITE)

fun ApplicationCall.canWrite(resource: SecuredResource): Boolean =
  hasPermission(resource, Permission.WRITE)

/**
 * Domain-facing convenience form of [hasAccess] for [Permission.WRITE].
 */
suspend fun <R> ApplicationCall.canWrite(resource: R, authorizer: Authorizer<AccessSubject, R>): Boolean =
  hasAccess(resource, Permission.WRITE, authorizer)

fun ApplicationCall.canManage(acl: Acl): Boolean =
  hasPermission(acl, Permission.MANAGE)

fun ApplicationCall.canManage(resource: SecuredResource): Boolean =
  hasPermission(resource, Permission.MANAGE)

/**
 * Domain-facing convenience form of [hasAccess] for [Permission.MANAGE].
 */
suspend fun <R> ApplicationCall.canManage(resource: R, authorizer: Authorizer<AccessSubject, R>): Boolean =
  hasAccess(resource, Permission.MANAGE, authorizer)
