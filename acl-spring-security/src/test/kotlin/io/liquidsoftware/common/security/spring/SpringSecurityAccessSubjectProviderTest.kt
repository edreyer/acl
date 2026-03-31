package io.liquidsoftware.common.security.spring

import io.liquidsoftware.common.security.acl.ANONYMOUS_SUBJECT_ID
import io.liquidsoftware.common.security.acl.AccessSubject
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User

class SpringSecurityAccessSubjectProviderTest {

  private val provider = SpringSecurityAccessSubjectProvider(
    AuthenticationAccessSubjectResolver(::resolveSubject),
  )

  @AfterEach
  fun clearSecurityContext() {
    SecurityContextHolder.clearContext()
  }

  @Test
  fun `currentSubject returns anonymous subject when no authentication exists`() {
    val subject = provider.currentSubject()

    assertEquals(ANONYMOUS_SUBJECT_ID, subject.userId)
    assertEquals(emptySet<String>(), subject.roles)
  }

  @Test
  fun `currentSubject returns authenticated user id and roles`() {
    authenticate("u_test-user", "ROLE_USER", "ROLE_ADMIN")

    val subject = provider.currentSubject()

    assertEquals("u_test-user", subject.userId)
    assertEquals(setOf("ROLE_USER", "ROLE_ADMIN"), subject.roles)
  }

  private fun authenticate(userId: String, vararg roles: String) {
    val authorities = roles.map(::SimpleGrantedAuthority)
    val principal = User("$userId@example.com", "", authorities)
    SecurityContextHolder.getContext().authentication =
      UsernamePasswordAuthenticationToken(principal, userId, principal.authorities)
  }

  private fun resolveSubject(authentication: Authentication?): AccessSubject =
    when (authentication) {
      is UsernamePasswordAuthenticationToken -> AccessSubject(
        userId = authentication.credentials as? String ?: ANONYMOUS_SUBJECT_ID,
        roles = authentication.authorities.mapNotNull { it.authority }.toSet(),
      )

      else -> AccessSubject(
        userId = ANONYMOUS_SUBJECT_ID,
        roles = emptySet(),
      )
    }
}
