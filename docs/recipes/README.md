# Recipes

Short, copyable answers to "how do I do this with acl?". The [tutorial](../tutorial.md)
teaches the library from the ground up; these start from a problem you already have.

| Recipe | What it shows | Compiled |
| --- | --- | --- |
| [Roles and permissions](roles-and-permissions.md) | Turning stored roles into permissions on the subject, and keeping roles out of the rules | Yes |
| [Multi-tenancy](multi-tenancy.md) | A tenant check in every rule, a test that catches the one you forgot, and why `policy<TenantOwned>` doesn't stack | Yes |
| [Lists and queries](lists-and-queries.md) | Narrowing in the database and confirming with the catalog, full pages, per-row buttons, lazy relations | Yes |
| [Denials as results](denials-as-results.md) | Sealed results instead of exceptions, 403 versus 404, and an Arrow `Raise` helper | Yes, except the Arrow section |
| [Audit logging](audit-logging.md) | Recording decisions at the action boundary without logging personal data | Yes |
| [Permission matrix tests](permission-matrix-tests.md) | One table of who may do what, where everything not listed must be denied | Yes |
| [Spring](spring.md) | The catalog as a bean, the current user from Spring Security, one `@RestControllerAdvice`, `@PreAuthorize` | No |
| [Ktor](ktor.md) | A principal that carries your user, checks in routes, one `StatusPages` handler | No |

Compiled recipes are run by the tests under
[`src/test/kotlin/io/liquidsoftware/acl/recipes`](../../src/test/kotlin/io/liquidsoftware/acl/recipes),
so the results in their comments are the results you get. Recipes marked "No" are written
against the frameworks' public APIs as of late 2026 (Spring Boot 3, Ktor 3, Arrow 2) but
are not built in this repository, since the library has no framework dependencies; check
them against the versions you use.
