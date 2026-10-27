# Spring

> Not compiled: this recipe is checked by reading, not by the build. It targets Spring
> Boot 3 (Spring Framework 6, Spring Security 6).

The library knows nothing about Spring, and doesn't need to. Spring Security answers
"who is this?"; the catalog answers "may they do this to that?". The glue is a bean, a
current-user lookup and one exception handler.

## The catalog is a bean

Build it once. It is immutable and thread-safe, so a singleton bean is exactly right:

```kotlin
@Configuration
class AclConfig {
    @Bean
    fun acl(): AclCatalog<User> = aclCatalog {
        register(notePolicy)
        register(notebookPolicy)
    }
}
```

Keep each policy as a top-level `val` next to the resource it protects (see the
[tutorial, step 6](../tutorial.md#6-more-resource-types-and-policies-in-their-own-files)),
so the policies stay plain Kotlin and the config only lists them.

## The current user

Load your domain `User` when Spring Security authenticates the request, and carry it on
the principal, so checks don't hit the database again:

```kotlin
class AppUserDetails(val user: User, private val passwordHash: String) : UserDetails {
    override fun getUsername() = user.id
    override fun getPassword() = passwordHash
    override fun getAuthorities() = emptyList<GrantedAuthority>()
}
```

With a JWT resource server, do the same in a `Converter<Jwt, AbstractAuthenticationToken>`
that loads the user from the token's subject. Either way, controllers ask for it with
`@AuthenticationPrincipal`.

## Check in the service

Put the check where the resource is loaded, in the service, so every way in (REST, a
scheduled job, a message listener) goes through it:

```kotlin
class AclDeniedException(val reason: DenialReason, val hideExistence: Boolean) : RuntimeException(reason.message)

@Service
class NoteService(private val acl: AclCatalog<User>, private val notes: NoteRepository) {
    @Transactional
    fun edit(user: User, noteId: String, text: String): Note {
        val note = notes.findByIdOrNull(noteId) ?: throw NoteNotFoundException(noteId)
        val decision = acl.decide(user, Write, note)
        if (decision is AccessDecision.Denied) {
            throw AclDeniedException(decision.reason, hideExistence = !acl.canRead(user, note))
        }
        note.text = text
        return note
    }
}

@RestController
class NoteController(private val service: NoteService) {
    @PutMapping("/notes/{id}")
    fun edit(@PathVariable id: String, @RequestBody body: EditNote, @AuthenticationPrincipal principal: AppUserDetails): NoteDto =
        service.edit(principal.user, id, body.text).toDto()
}
```

The check runs inside `@Transactional`, so a rule that reads a lazy relation still has a
session. Better still, fetch what the rules read with the query; see
[Lists and queries](lists-and-queries.md).

Name the exception something other than `AccessDeniedException`: Spring Security already
has one, and its `ExceptionTranslationFilter` treats it as "please log in" for anonymous
requests.

## One handler for every denial

```kotlin
@RestControllerAdvice
class AccessAdvice {
    private val log = LoggerFactory.getLogger(javaClass)

    @ExceptionHandler(AclDeniedException::class)
    fun denied(exception: AclDeniedException): ResponseEntity<ProblemDetail> {
        log.info("Access denied: {}", exception.reason.message)
        val status = if (exception.hideExistence) HttpStatus.NOT_FOUND else HttpStatus.FORBIDDEN
        return ResponseEntity.status(status).body(ProblemDetail.forStatus(status))
    }
}
```

`reason.message` goes to the log, not the response: it names your classes. Answering 404
to users who can't even read the resource keeps ids from being probed; see
[Denials as results](denials-as-results.md#403-or-404).

## `@PreAuthorize`, if you prefer annotations

Method security can call a bean, so the catalog works there too:

```kotlin
@Component("noteAccess")
class NoteAccess(private val acl: AclCatalog<User>, private val notes: NoteRepository) {
    fun canRead(authentication: Authentication, noteId: String): Boolean {
        val user = (authentication.principal as AppUserDetails).user
        val note = notes.findByIdOrNull(noteId) ?: return false
        return acl.canRead(user, note)
    }
}

@PreAuthorize("@noteAccess.canRead(authentication, #id)")
@GetMapping("/notes/{id}")
fun note(@PathVariable id: String): NoteDto = service.find(id).toDto()
```

It needs `@EnableMethodSecurity`, and it costs something: the note is loaded twice, the
denial reason is lost, and a missing note becomes a 403. Prefer the service check for
anything that loads a resource; annotations suit checks on the subject alone.
