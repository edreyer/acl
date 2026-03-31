package io.liquidsoftware.common.security.spring

import io.liquidsoftware.common.security.acl.AccessSubject
import org.springframework.security.core.context.SecurityContextHolder

/**
 * Resolves the current Spring Security subject as an [AccessSubject].
 *
 * Keep authorization checks in [io.liquidsoftware.common.security.spring.arrow.SpringSecurityAclChecker]
 * so this type stays focused on subject resolution only.
 */
class SpringSecurityAccessSubjectProvider(
  private val resolver: AuthenticationAccessSubjectResolver,
) {
  fun currentSubject(): AccessSubject =
    resolver.resolve(SecurityContextHolder.getContext().authentication)
}
