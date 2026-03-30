package io.liquidsoftware.common.security.spring.arrow

import arrow.core.Either
import arrow.core.raise.either
import assertk.assertThat
import assertk.assertions.isEqualTo
import assertk.assertions.isInstanceOf
import io.liquidsoftware.common.security.acl.ANONYMOUS_SUBJECT_ID
import io.liquidsoftware.common.security.acl.AccessDenied
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.AclRole
import io.liquidsoftware.common.security.acl.AuthorizationError
import io.liquidsoftware.common.security.acl.Authorizer
import io.liquidsoftware.common.security.acl.DenialContext
import io.liquidsoftware.common.security.acl.Permission
import io.liquidsoftware.common.security.acl.authorizer
import io.liquidsoftware.common.security.spring.SpringSecurityAccessSubjectProvider
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User

class SpringSecurityAclCheckerTest {

  private data class Document(
    val id: String,
    val ownerId: String,
  )

  private val checker = SpringSecurityAclChecker(
    SpringSecurityAccessSubjectProvider { authentication ->
      when (authentication) {
        is UsernamePasswordAuthenticationToken -> AccessSubject(
          userId = authentication.credentials as? String ?: "u_anonymous",
          roles = authentication.authorities.mapNotNull { it.authority }.toSet(),
        )

        else -> AccessSubject(
          userId = "u_anonymous",
          roles = emptySet(),
        )
      }
    },
  )

  private val documentAccess: Authorizer<AccessSubject, Document> =
    authorizer {
      canManage { subject, document ->
        subject.userId == document.ownerId || AclChecker.ROLE_ADMIN in subject.roles
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

    val result = either {
      checker.ensureCanManage(acl)
    }

    assertThat(result is Either.Right).isEqualTo(true)
  }

  @Test
  fun `ensureCanRead raises AccessDenied with acl context for anonymous subject without access`() = runBlocking {
    val acl = Acl.of("a_test", "someone-else", AclRole.READER)

    val result = either {
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

  @Test
  fun `ensureCanRead supports authorizers with current subject`() = runBlocking {
    authenticate("u_reader", "ROLE_READER")
    val document = Document(id = "doc-1", ownerId = "u_owner")

    val result = either {
      checker.ensureCanRead(document, documentAccess)
    }

    assertThat(result is Either.Right).isEqualTo(true)
  }

  @Test
  fun `ensureHasAccess raises AccessDenied with unknown context for denied authorizer access`() = runBlocking {
    authenticate("u_reader", "ROLE_READER")
    val document = Document(id = "doc-1", ownerId = "u_owner")

    val result = either {
      checker.ensureHasAccess(document, Permission.WRITE, documentAccess)
    }

    val error = (result as Either.Left).value
    assertThat(error).isInstanceOf(AccessDenied::class)
    error as AccessDenied
    assertThat(error.permission).isEqualTo(Permission.WRITE)
    assertThat(error.context).isEqualTo(DenialContext.Unknown)
  }

  private fun authenticate(userId: String, vararg roles: String) {
    val authorities = roles.map(::SimpleGrantedAuthority)
    val principal = User("$userId@example.com", "", authorities)
    SecurityContextHolder.getContext().authentication =
      UsernamePasswordAuthenticationToken(principal, userId, principal.authorities)
  }
}
