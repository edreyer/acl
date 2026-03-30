package io.liquidsoftware.common.security.ktor

import assertk.assertThat
import assertk.assertions.isEqualTo
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.bearer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import io.liquidsoftware.common.security.acl.AccessSubject
import io.liquidsoftware.common.security.acl.ANONYMOUS_SUBJECT_ID
import io.liquidsoftware.common.security.acl.Acl
import io.liquidsoftware.common.security.acl.AclChecker
import io.liquidsoftware.common.security.acl.AclRole
import io.liquidsoftware.common.security.acl.Authorizer
import io.liquidsoftware.common.security.acl.Permission
import io.liquidsoftware.common.security.acl.SecuredResource
import io.liquidsoftware.common.security.acl.authorizer
import org.junit.jupiter.api.Test

class AclKtorTest {

  data class TestPrincipal(
    val userId: String,
    val roles: Set<String>,
  )

  private data class TestResource(
    private val resourceAcl: Acl,
  ) : SecuredResource {
    override fun acl(): Acl = resourceAcl
  }

  private data class Document(
    val id: String,
    val ownerId: String,
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

  @Test
  fun `currentSubject returns anonymous subject when no principal exists`() = testApplication {
    application {
      install(AclKtor) {
        resolver = principalAccessSubjectResolver<TestPrincipal>(
          userId = TestPrincipal::userId,
          roles = TestPrincipal::roles,
        )
      }

      routing {
        get("/subject") {
          val subject = call.currentSubject()
          call.respondText("${subject.userId}:${subject.roles.size}")
        }
      }
    }

    val response = client.get("/subject")

    assertThat(response.bodyAsText()).isEqualTo("$ANONYMOUS_SUBJECT_ID:0")
  }

  @Test
  fun `currentSubject resolves principal from authenticated call`() = testApplication {
    application {
      install(Authentication) {
        bearer("auth-bearer") {
          authenticate { tokenCredential ->
            when (tokenCredential.token) {
              "user-token" -> TestPrincipal("u_test-user", setOf("ROLE_USER"))
              "admin-token" -> TestPrincipal("u_admin", setOf(AclChecker.ROLE_ADMIN))
              else -> null
            }
          }
        }
      }

      install(AclKtor) {
        resolver = principalAccessSubjectResolver<TestPrincipal>(
          userId = TestPrincipal::userId,
          roles = TestPrincipal::roles,
        )
      }

      routing {
        authenticate("auth-bearer") {
          get("/subject") {
            val subject = call.currentSubject()
            call.respondText("${subject.userId}:${subject.roles.single()}")
          }
        }
      }
    }

    val response = client.get("/subject") {
      header(HttpHeaders.Authorization, "Bearer user-token")
    }

    assertThat(response.bodyAsText()).isEqualTo("u_test-user:ROLE_USER")
  }

  @Test
  fun `canRead uses current subject from authenticated call`() = testApplication {
    application {
      install(Authentication) {
        bearer("auth-bearer") {
          authenticate { tokenCredential ->
            when (tokenCredential.token) {
              "user-token" -> TestPrincipal("u_test-user", setOf("ROLE_USER"))
              else -> null
            }
          }
        }
      }

      install(AclKtor) {
        resolver = principalAccessSubjectResolver<TestPrincipal>(
          userId = TestPrincipal::userId,
          roles = TestPrincipal::roles,
        )
      }

      routing {
        authenticate("auth-bearer") {
          get("/read") {
            val allowed = call.canRead(Acl.of("a_test", "u_test-user", AclRole.READER))
            call.respondText(allowed.toString())
          }
        }
      }
    }

    val response = client.get("/read") {
      header(HttpHeaders.Authorization, "Bearer user-token")
    }

    assertThat(response.bodyAsText()).isEqualTo("true")
  }

  @Test
  fun `canManage supports secured resources and admin bypass`() = testApplication {
    application {
      install(Authentication) {
        bearer("auth-bearer") {
          authenticate { tokenCredential ->
            when (tokenCredential.token) {
              "admin-token" -> TestPrincipal("u_admin", setOf(AclChecker.ROLE_ADMIN))
              else -> null
            }
          }
        }
      }

      install(AclKtor) {
        resolver = principalAccessSubjectResolver<TestPrincipal>(
          userId = TestPrincipal::userId,
          roles = TestPrincipal::roles,
        )
      }

      routing {
        authenticate("auth-bearer") {
          get("/manage") {
            val resource = TestResource(Acl.of("a_test", "someone-else", AclRole.READER))
            call.respondText(call.canManage(resource).toString())
          }
        }
      }
    }

    val response = client.get("/manage") {
      header(HttpHeaders.Authorization, "Bearer admin-token")
    }

    assertThat(response.bodyAsText()).isEqualTo("true")
  }

  @Test
  fun `principal resolver defaults roles to empty set when roles mapping is omitted`() = testApplication {
    application {
      install(Authentication) {
        bearer("auth-bearer") {
          authenticate { tokenCredential ->
            when (tokenCredential.token) {
              "user-token" -> TestPrincipal("u_test-user", setOf("ROLE_USER"))
              else -> null
            }
          }
        }
      }

      install(AclKtor) {
        resolver = principalAccessSubjectResolver<TestPrincipal>(
          userId = TestPrincipal::userId,
        )
      }

      routing {
        authenticate("auth-bearer") {
          get("/subject") {
            val subject = call.currentSubject()
            call.respondText("${subject.userId}:${subject.roles.size}")
          }
        }
      }
    }

    val response = client.get("/subject") {
      header(HttpHeaders.Authorization, "Bearer user-token")
    }

    assertThat(response.bodyAsText()).isEqualTo("u_test-user:0")
  }

  @Test
  fun `currentSubject is resolved once per call`() = testApplication {
    var resolveCount = 0

    application {
      install(AclKtor) {
        resolver = ApplicationCallAccessSubjectResolver {
          resolveCount += 1
          AccessSubject("u_cached", emptySet())
        }
      }

      routing {
        get("/subject") {
          val first = call.currentSubject()
          val second = call.currentSubject()
          call.respondText("${first.userId}:${second.userId}:$resolveCount")
        }
      }
    }

    val response = client.get("/subject")

    assertThat(response.bodyAsText()).isEqualTo("u_cached:u_cached:1")
  }

  @Test
  fun `canWrite returns false for denied secured resource access`() = testApplication {
    application {
      install(Authentication) {
        bearer("auth-bearer") {
          authenticate { tokenCredential ->
            when (tokenCredential.token) {
              "user-token" -> TestPrincipal("u_test-user", setOf("ROLE_USER"))
              else -> null
            }
          }
        }
      }

      install(AclKtor) {
        resolver = principalAccessSubjectResolver<TestPrincipal>(
          userId = TestPrincipal::userId,
          roles = TestPrincipal::roles,
        )
      }

      routing {
        authenticate("auth-bearer") {
          get("/write") {
            val resource = TestResource(Acl.of("a_test", "u_test-user", AclRole.READER))
            call.respondText(call.canWrite(resource).toString())
          }
        }
      }
    }

    val response = client.get("/write") {
      header(HttpHeaders.Authorization, "Bearer user-token")
    }

    assertThat(response.bodyAsText()).isEqualTo("false")
  }

  @Test
  fun `canRead supports authorizers with current subject`() = testApplication {
    application {
      install(Authentication) {
        bearer("auth-bearer") {
          authenticate { tokenCredential ->
            when (tokenCredential.token) {
              "reader-token" -> TestPrincipal("u_reader", setOf("ROLE_READER"))
              else -> null
            }
          }
        }
      }

      install(AclKtor) {
        resolver = principalAccessSubjectResolver<TestPrincipal>(
          userId = TestPrincipal::userId,
          roles = TestPrincipal::roles,
        )
      }

      routing {
        authenticate("auth-bearer") {
          get("/document/read") {
            val document = Document(id = "doc-1", ownerId = "u_owner")
            call.respondText(call.canRead(document, documentAccess).toString())
          }
        }
      }
    }

    val response = client.get("/document/read") {
      header(HttpHeaders.Authorization, "Bearer reader-token")
    }

    assertThat(response.bodyAsText()).isEqualTo("true")
  }

  @Test
  fun `hasAccess supports authorizers with denied current subject`() = testApplication {
    application {
      install(Authentication) {
        bearer("auth-bearer") {
          authenticate { tokenCredential ->
            when (tokenCredential.token) {
              "reader-token" -> TestPrincipal("u_reader", setOf("ROLE_READER"))
              else -> null
            }
          }
        }
      }

      install(AclKtor) {
        resolver = principalAccessSubjectResolver<TestPrincipal>(
          userId = TestPrincipal::userId,
          roles = TestPrincipal::roles,
        )
      }

      routing {
        authenticate("auth-bearer") {
          get("/document/write") {
            val document = Document(id = "doc-1", ownerId = "u_owner")
            call.respondText(call.hasAccess(document, Permission.WRITE, documentAccess).toString())
          }
        }
      }
    }

    val response = client.get("/document/write") {
      header(HttpHeaders.Authorization, "Bearer reader-token")
    }

    assertThat(response.bodyAsText()).isEqualTo("false")
  }
}
