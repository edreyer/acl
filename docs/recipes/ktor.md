# Ktor

> Not compiled: this recipe is checked by reading, not by the build. It targets Ktor 3
> with the `Authentication` and `StatusPages` plugins.

Ktor's `Authentication` plugin answers "who is this?"; the catalog answers "may they do
this to that?". The glue is a principal that carries your user, a check in the route or
service, and one `StatusPages` handler.

## A principal that carries your user

Load the domain user when the credentials are validated, so checks don't load it again:

```kotlin
data class UserPrincipal(val user: User)

fun Application.configureAuth(users: UserRepository) {
    install(Authentication) {
        jwt("auth-jwt") {
            verifier(jwtVerifier)
            validate { credential -> users.find(credential.payload.subject)?.let(::UserPrincipal) }
        }
    }
}

fun ApplicationCall.currentUser(): User =
    principal<UserPrincipal>()?.user ?: error("This route is not inside authenticate { }")
```

## Check, then act

Build the catalog once, when the module starts; it's immutable and safe to share between
coroutines. The route loads the note, checks it, then acts:

```kotlin
class AclDeniedException(val reason: DenialReason, val hideExistence: Boolean) : RuntimeException(reason.message)

fun <S : Any> AclCatalog<S>.requireAccess(subject: S, operation: Operation, resource: Any) {
    val decision = decide(subject, operation, resource)
    if (decision is AccessDecision.Denied) {
        throw AclDeniedException(decision.reason, hideExistence = !canRead(subject, resource))
    }
}

fun Application.configureRoutes(acl: AclCatalog<User>, notes: NoteRepository) {
    routing {
        authenticate("auth-jwt") {
            get("/notes/{id}") {
                val note = notes.find(call.parameters.getOrFail("id")) ?: return@get call.respond(HttpStatusCode.NotFound)
                acl.requireAccess(call.currentUser(), Read, note)
                call.respond(note.toDto())
            }
            get("/notes") {
                val user = call.currentUser()
                val access = acl.forSubject(user)
                call.respond(notes.candidatesFor(user).filter(access::canRead).map { it.toDto() })
            }
        }
    }
}
```

For anything beyond a lookup, move the check into a service so other entry points share
it, as in the [Spring recipe](spring.md#check-in-the-service).

Rules aren't `suspend`, so they can't fetch anything. Load what they read (the note's
sharing list, the user's teams) before the check, in the repository call that loads the
resource.

## One handler for every denial

```kotlin
fun Application.configureErrors() {
    install(StatusPages) {
        exception<AclDeniedException> { call, cause ->
            call.application.log.info("Access denied: ${cause.reason.message}")
            call.respond(if (cause.hideExistence) HttpStatusCode.NotFound else HttpStatusCode.Forbidden)
        }
    }
}
```

`reason.message` goes to the log, not the response. Answering 404 to users who can't
even read the resource keeps ids from being probed; see
[Denials as results](denials-as-results.md#403-or-404), which also shows how to skip the
exception and return a sealed result instead.
