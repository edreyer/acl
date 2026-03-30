package io.liquidsoftware.common.security.spring

import assertk.assertThat
import assertk.assertions.contains
import assertk.assertions.isEqualTo
import io.liquidsoftware.common.security.acl.ANONYMOUS_SUBJECT_ID
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclRole
import io.liquidsoftware.common.security.acl.Authorizer
import io.liquidsoftware.common.security.acl.Permission
import io.liquidsoftware.common.security.acl.authorizer
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User

class SpringSecurityAccessSubjectProviderTest {

  private data class Document(
    val id: String,
    val ownerId: String,
  )

  private val provider = SpringSecurityAccessSubjectProvider(
    AuthenticationAccessSubjectResolver(::resolveSubject),
  )

  private val documentAccess: Authorizer<AccessSubject, Document> =
    authorizer {
      canManage { subject, document ->
        subject.userId == document.ownerId || "ROLE_ADMIN" in subject.roles
      }

      canWrite { subject, document ->
        canManage(subject, document) || "ROLE_EDITOR" in subject.roles
      }

      canRead { subject, document ->
        canWrite(subject, document) || "ROLE_READER" in subject.roles
      }
    }

  @AfterEach
  fun clearSecurityContext() {
    SecurityContextHolder.clearContext()
  }

  @Test
  fun `currentSubject returns anonymous subject when no authentication exists`() {
    val subject = provider.currentSubject()

    assertThat(subject.userId).isEqualTo(ANONYMOUS_SUBJECT_ID)
    assertThat(subject.roles).isEqualTo(emptySet())
  }

  @Test
  fun `currentSubject returns authenticated user id and roles`() {
    authenticate("u_test-user", "ROLE_USER", "ROLE_ADMIN")

    val subject = provider.currentSubject()

    assertThat(subject.userId).isEqualTo("u_test-user")
    assertThat(subject.roles).contains("ROLE_USER")
    assertThat(subject.roles).contains("ROLE_ADMIN")
  }

  @Test
  fun `hasPermission uses current subject`() = runBlocking {
    authenticate("u_test-user", "ROLE_USER")
    val acl = Acl.of("a_test", "u_test-user", AclRole.READER)

    val result = provider.hasPermission(acl, Permission.READ)

    assertThat(result).isEqualTo(true)
  }

  @Test
  fun `hasPermission returns false when current subject lacks access`() = runBlocking {
    authenticate("u_test-user", "ROLE_USER")
    val acl = Acl.of("a_test", "someone-else", AclRole.READER)

    val result = provider.hasPermission(acl, Permission.READ)

    assertThat(result).isEqualTo(false)
  }

  @Test
  fun `hasPermission accepts explicit subject without security context`() = runBlocking {
    val acl = Acl.of("a_test", "u_test-user", AclRole.READER)
    val subject = AccessSubject("u_test-user", emptySet())

    val result = provider.hasPermission(acl, subject, Permission.READ)

    assertThat(result).isEqualTo(true)
  }

  @Test
  fun `hasPermission uses admin bypass for current subject`() = runBlocking {
    authenticate("u_admin", "ROLE_ADMIN")
    val acl = Acl.of("a_test", "someone-else", AclRole.READER)

    val result = provider.hasPermission(acl, Permission.MANAGE)

    assertThat(result).isEqualTo(true)
  }

  @Test
  fun `canRead supports authorizers with current subject`() = runBlocking {
    authenticate("u_reader", "ROLE_READER")
    val document = Document(id = "doc-1", ownerId = "u_owner")

    val result = provider.canRead(document, documentAccess)

    assertThat(result).isEqualTo(true)
  }

  @Test
  fun `hasAccess supports authorizers with current subject`() = runBlocking {
    authenticate("u_reader", "ROLE_READER")
    val document = Document(id = "doc-1", ownerId = "u_owner")

    val result = provider.hasAccess(document, Permission.WRITE, documentAccess)

    assertThat(result).isEqualTo(false)
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
