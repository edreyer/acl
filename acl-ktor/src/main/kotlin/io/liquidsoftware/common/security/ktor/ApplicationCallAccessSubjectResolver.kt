package io.liquidsoftware.common.security.ktor

import io.ktor.server.application.ApplicationCall
import io.ktor.server.auth.principal
import io.liquidsoftware.common.security.acl.ANONYMOUS_SUBJECT_ID
import io.liquidsoftware.common.security.acl.AccessSubject

fun interface ApplicationCallAccessSubjectResolver {
  fun resolve(call: ApplicationCall): AccessSubject
}

inline fun <reified T : Any> principalAccessSubjectResolver(
  anonymousSubjectId: String = ANONYMOUS_SUBJECT_ID,
  crossinline userId: (T) -> String,
  crossinline roles: (T) -> Set<String> = { emptySet() },
): ApplicationCallAccessSubjectResolver =
  ApplicationCallAccessSubjectResolver { call ->
    val principal = call.principal<T>()
    if (principal == null) {
      AccessSubject(
        userId = anonymousSubjectId,
        roles = emptySet(),
      )
    } else {
      AccessSubject(
        userId = userId(principal),
        roles = roles(principal),
      )
    }
  }
