package io.liquidsoftware.common.security.spring.arrow

import arrow.core.Either
import arrow.core.raise.either
import assertk.assertThat
import assertk.assertions.isEqualTo
import assertk.assertions.isInstanceOf
import io.liquidsoftware.common.security.acl.ANONYMOUS_SUBJECT_ID
import io.liquidsoftware.common.security.acl.AccessDenied
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.AclRole
import io.liquidsoftware.common.security.acl.AuthorizationError
import io.liquidsoftware.common.security.acl.DenialContext
import io.liquidsoftware.common.security.acl.Permission
import io.liquidsoftware.common.security.spring.AuthenticationAccessSubjectResolver
import io.liquidsoftware.common.security.spring.SpringSecurityAccessSubjectProvider
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User

class SpringSecurityAclCheckerTest {

  private val checker = SpringSecurityAclChecker(
    SpringSecurityAccessSubjectProvider(
      AuthenticationAccessSubjectResolver { authentication ->
        when (authentication) {
          is UsernamePasswordAuthenticationToken -> io.liquidsoftware.common.security.acl.AccessSubject(
            userId = authentication.credentials as? String ?: "u_anonymous",
            roles = authentication.authorities.mapNotNull { it.authority }.toSet(),
          )

          else -> io.liquidsoftware.common.security.acl.AccessSubject(
            userId = "u_anonymous",
            roles = emptySet(),
          )
        }
      },
    ),
  )

  @AfterEach
  fun clearSecurityContext() {
    SecurityContextHolder.clearContext()
  }

  @Test
  fun `ensureCanRead uses current subject and succeeds for allowed access`() = runBlocking {
    authenticate("u_test-user", "ROLE_USER")
    val acl = Acl.of("a_test", "u_test-user", AclRole.READER)

    val result = either<AuthorizationError, Unit> {
      checker.ensureCanRead(acl)
    }

    assertThat(result is Either.Right).isEqualTo(true)
  }

  @Test
  fun `ensureCanWrite uses current subject and raises AccessDenied with acl context for denied access`() = runBlocking {
    authenticate("u_test-user", "ROLE_USER")
    val acl = Acl.of("a_test", "u_test-user", AclRole.READER)

    val result = either<AuthorizationError, Unit> {
      checker.ensureCanWrite(acl)
    }

    val error = (result as Either.Left).value
    assertThat(error).isInstanceOf(AccessDenied::class)
    error as AccessDenied
    val context = error.context
    assertThat(context).isInstanceOf(DenialContext.Acl::class)
    context as DenialContext.Acl
    assertThat(context.resourceId).isEqualTo("a_test")
    assertThat(error.permission).isEqualTo(Permission.WRITE)
    assertThat(context.subjectId).isEqualTo("u_test-user")
  }

  @Test
  fun `ensureCanManage uses admin bypass and succeeds`() = runBlocking {
    authenticate("u_admin", AclChecker.ROLE_ADMIN)
    val acl = Acl.of("a_test", "someone-else", AclRole.READER)

    val result = either<AuthorizationError, Unit> {
      checker.ensureCanManage(acl)
    }

    assertThat(result is Either.Right).isEqualTo(true)
  }

  @Test
  fun `ensureCanRead raises AccessDenied with acl context for anonymous subject without access`() = runBlocking {
    val acl = Acl.of("a_test", "someone-else", AclRole.READER)

    val result = either<AuthorizationError, Unit> {
      checker.ensureCanRead(acl)
    }

    val error = (result as Either.Left).value
    assertThat(error).isInstanceOf(AccessDenied::class)
    error as AccessDenied
    val context = error.context
    assertThat(context).isInstanceOf(DenialContext.Acl::class)
    context as DenialContext.Acl
    assertThat(context.resourceId).isEqualTo("a_test")
    assertThat(error.permission).isEqualTo(Permission.READ)
    assertThat(context.subjectId).isEqualTo(ANONYMOUS_SUBJECT_ID)
  }

  private fun authenticate(userId: String, vararg roles: String) {
    val authorities = roles.map(::SimpleGrantedAuthority)
    val principal = User("$userId@example.com", "", authorities)
    SecurityContextHolder.getContext().authentication =
      UsernamePasswordAuthenticationToken(principal, userId, principal.authorities)
  }
}
