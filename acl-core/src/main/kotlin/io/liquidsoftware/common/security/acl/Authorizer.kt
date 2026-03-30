package io.liquidsoftware.common.security.acl

private typealias AuthorizerRule<S, R> = suspend RuleScope<S, R>.(S, R) -> Boolean

private data class EvaluationFrame<S, R>(
  val subject: S,
  val resource: R,
  val permission: Permission,
)

interface Authorizer<S, R> {
  suspend fun canRead(subject: S, resource: R): Boolean =
    hasAccess(subject, resource, Permission.READ)

  suspend fun canWrite(subject: S, resource: R): Boolean =
    hasAccess(subject, resource, Permission.WRITE)

  suspend fun canManage(subject: S, resource: R): Boolean =
    hasAccess(subject, resource, Permission.MANAGE)

  suspend fun hasAccess(subject: S, resource: R, permission: Permission): Boolean
}

/**
 * Evaluation scope available inside authorizer rules.
 *
 * Rule evaluation is intended to stay within a single coroutine. Rule bodies
 * should not fan out concurrent calls like `async { canRead(...) }` against the
 * same scope, because permission composition is tracked with mutable
 * evaluation-state for cycle detection.
 */
interface RuleScope<S, R> {
  suspend fun canRead(subject: S, resource: R): Boolean
  suspend fun canWrite(subject: S, resource: R): Boolean
  suspend fun canManage(subject: S, resource: R): Boolean
  suspend fun hasAccess(subject: S, resource: R, permission: Permission): Boolean
}

interface AuthorizerDslScope<S, R> {
  fun canRead(rule: AuthorizerRule<S, R>)
  fun canWrite(rule: AuthorizerRule<S, R>)
  fun canManage(rule: AuthorizerRule<S, R>)
}

internal class AuthorizerDsl<S, R> : AuthorizerDslScope<S, R> {
  private val rules = mutableMapOf<Permission, AuthorizerRule<S, R>>()

  override fun canRead(rule: AuthorizerRule<S, R>) {
    check(Permission.READ !in rules) {
      "canRead rule is already defined"
    }
    rules[Permission.READ] = rule
  }

  override fun canWrite(rule: AuthorizerRule<S, R>) {
    check(Permission.WRITE !in rules) {
      "canWrite rule is already defined"
    }
    rules[Permission.WRITE] = rule
  }

  override fun canManage(rule: AuthorizerRule<S, R>) {
    check(Permission.MANAGE !in rules) {
      "canManage rule is already defined"
    }
    rules[Permission.MANAGE] = rule
  }

  internal fun build(): Authorizer<S, R> =
    RuleBasedAuthorizer(rules.toMap())
}

fun <S, R> authorizer(init: AuthorizerDslScope<S, R>.() -> Unit): Authorizer<S, R> =
  AuthorizerDsl<S, R>().apply(init).build()

private class RuleBasedAuthorizer<S, R>(
  private val rules: Map<Permission, AuthorizerRule<S, R>>,
) : Authorizer<S, R> {

  override suspend fun hasAccess(subject: S, resource: R, permission: Permission): Boolean =
    EvaluationScope().hasAccess(subject, resource, permission)

  // This scope tracks recursive permission composition for a single evaluation
  // and is not designed for concurrent use from multiple coroutines.
  private inner class EvaluationScope : RuleScope<S, R> {
    private val evaluationStack = ArrayDeque<EvaluationFrame<S, R>>()

    override suspend fun canRead(subject: S, resource: R): Boolean =
      hasAccess(subject, resource, Permission.READ)

    override suspend fun canWrite(subject: S, resource: R): Boolean =
      hasAccess(subject, resource, Permission.WRITE)

    override suspend fun canManage(subject: S, resource: R): Boolean =
      hasAccess(subject, resource, Permission.MANAGE)

    override suspend fun hasAccess(subject: S, resource: R, permission: Permission): Boolean {
      val rule = rules[permission] ?: return false
      val frame = EvaluationFrame(subject, resource, permission)

      check(frame !in evaluationStack) {
        "Circular authorizer rule dependency detected for permission $permission"
      }

      evaluationStack.addLast(frame)
      return try {
        rule(subject, resource)
      } finally {
        evaluationStack.removeLast()
      }
    }
  }
}
