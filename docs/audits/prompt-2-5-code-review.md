# Prompt 2.5 Code Review

Reviewed commit: `002e84dd93eabc8bee076580d0320fa6b72000e2` (`hardering for production`)

Scope: latest commit implementing Prompt 2.5 from `final_audit.md`, with review limited to changed files and likely side effects in adjacent code paths.

## Summary

I did not find a critical authentication bypass, token-class confusion path, plaintext secret artifact, or obviously unbounded production hot path introduced by this commit.

The implementation materially improves token separation, session pagination, scheduler locking, audit durability, outbox state tracking, HIBP support, and release/observability artifacts. The issues below are real release risks, but none is an invented blocker or evidence of a currently exploitable privilege escalation.

## Findings

### 1. High-risk fail-closed abuse responses may bypass the intended 503 handler

Severity: High when `AUTH_ABUSE_FAIL_CLOSED_HIGH_RISK=true`; otherwise dormant by default.

References:

- `src/main/java/io/github/brenomega/authkit/infrastructure/network/rateLimit/EndpointAbuseRateLimitingFilter.java:40`
- `src/main/java/io/github/brenomega/authkit/infrastructure/network/rateLimit/EndpointAbuseRateLimitingFilter.java:45`
- `src/main/java/io/github/brenomega/authkit/infrastructure/security/AbuseThrottleService.java:72`
- `src/main/java/io/github/brenomega/authkit/infrastructure/security/AbuseThrottleService.java:103`

`AbuseThrottleService` throws `AbuseProtectionUnavailableException` when fail-closed mode is enabled and Redis is unavailable. Service-layer calls are handled by `GlobalExceptionHandler`, but the endpoint filter only catches `RateLimitExceededException`. Because this exception is raised from the security filter chain before controller execution, it can bypass the API exception envelope and intended opaque HTTP 503 behavior.

Impact:

- Login, MFA login verification, registration, recovery/reset, and OAuth token/revoke/introspect paths can return an unintended servlet/security-chain error during a Redis incident.
- The behavior contradicts `SYSTEM_USE_CASE_FLOWS.md:22`, which says the optional fail-closed mode returns opaque 503.
- This is not an auth bypass, but it weakens incident behavior exactly when a high-risk protective mode is enabled.

Recommendation:

- Catch `AbuseProtectionUnavailableException` or `ApiBaseException` in `EndpointAbuseRateLimitingFilter` and write a consistent `503` JSON response, or delegate to a `HandlerExceptionResolver` that is safe from filters.
- Add a MockMvc/integration test with fail-closed enabled, no Redis client, and `POST /api/v1/auth/login`, asserting HTTP 503 and the expected opaque response body.

### 2. `DEAD` email outbox rows are not terminal against stale successful delivery acknowledgements

Severity: Medium.

References:

- `src/main/java/io/github/brenomega/authkit/infrastructure/queue/outbox/EmailOutboxRepository.java:58`
- `src/main/java/io/github/brenomega/authkit/infrastructure/queue/outbox/EmailOutboxRepository.java:66`
- `src/main/java/io/github/brenomega/authkit/infrastructure/queue/outbox/EmailOutboxService.java:64`
- `src/main/java/io/github/brenomega/authkit/infrastructure/queue/outbox/EmailOutboxService.java:72`

`markFailed` treats `DEAD` as terminal and never retries it, but `markSent` updates any row whose status is not already `SENT`. That means a delayed Rabbit/direct worker success can flip a `DEAD` row to `SENT` after maximum retry exhaustion.

Impact:

- Terminal delivery state and alerting can be hidden after `security.email.outbox.dead` fires.
- Operators may lose the durable record that the system exhausted automatic retries.
- This is not a data confidentiality issue, but it weakens observability and incident reconciliation for email delivery.

Recommendation:

- Either make `DEAD` truly terminal by excluding it from `markSent`, or explicitly document that provider acceptance can override `DEAD`.
- Prefer a conditional update such as `status in (PROCESSING, QUEUED)` or `status <> SENT and status <> DEAD`, depending on the desired stale-success semantics.
- Add a test proving a `DEAD` row cannot be marked `SENT` by a stale acknowledgement if the terminal-state contract is intended.

### 3. Critical audit rollback documentation is broader than the code guarantee

Severity: Medium/Low, observability and release-contract risk.

References:

- `SYSTEM_USE_CASE_FLOWS.md:29`
- `src/main/java/io/github/brenomega/authkit/infrastructure/audit/SecurityEventWriter.java:21`
- `src/main/java/io/github/brenomega/authkit/service/AuthService.java:110`
- `src/main/java/io/github/brenomega/authkit/service/AuthService.java:151`
- `src/main/java/io/github/brenomega/authkit/service/AuthService.java:419`
- `src/main/java/io/github/brenomega/authkit/service/StepUpService.java:82`

Critical audit writes use `Propagation.REQUIRED`, so they participate in an existing database transaction when one exists. That is valid for transactional admin, MFA-disable, and deletion flows. However, some critical event sources mutate non-transactional Redis/local state or run outside a database transaction. Examples include login lockout state and refresh-token family compromise handling.

Impact:

- If critical audit persistence fails after `lockoutService.recordFailedAttempt`, the lockout counter may already be consumed while the critical audit event is denied.
- If refresh-family reuse is detected, Redis family revocation is already done before the critical audit record is attempted.
- These are generally safer fail-closed outcomes, but they are not "rolled back transactional mutations" in the broad sense currently documented.

Recommendation:

- Narrow the documentation to say database-backed transactional mutations roll back, while Redis/local security state may remain applied.
- If stronger behavior is required, wrap affected DB flows in transactions and define explicit handling for non-rollbackable Redis/local state.
- Add tests for audit failure in lockout and refresh-reuse paths so the accepted state semantics are deliberate.

## Residual Risks

- The OpenAPI contract test validates path/method parity, but not response schemas, parameters, or OAuth-vs-first-party bearer semantics. This is acceptable for the stated parity goal, but not full contract proof.
- HIBP is privacy-preserving and fail-open, but when enabled it adds synchronous outbound latency to registration/password-change/reset paths. The configured short timeouts help; load evidence remains Prompt 3.
- Docker-backed PostgreSQL/ShedLock and Redis HSCAN tests are present but were not run in this local sandbox review.

## Root Markdown Cleanup

Current root Markdown files:

- `README.md`: Keep. This is the project entrypoint.
- `CHANGELOG.md`: Keep. Needed for release/version discipline.
- `DEPLOYMENT.md`: Keep somewhere. It is operationally important; root placement is acceptable, though `docs/DEPLOYMENT.md` would reduce root clutter.
- `INTEGRATOR.md`: Keep somewhere. It is a real integration contract; consider moving to `docs/INTEGRATOR.md` and leaving a README link.
- `SECURITY_MODEL.md`: Keep somewhere. It is release-facing security documentation; consider moving to `docs/SECURITY_MODEL.md`.
- `SYSTEM_USE_CASE_FLOWS.md`: Useful for architecture/onboarding, but not necessary in the root. Move to `docs/architecture/SYSTEM_USE_CASE_FLOWS.md` if retained.
- `final_audit.md`: Not a production-facing product document. After extracting open issues into tickets and keeping this review, remove it from the root or move it to `docs/audits/final_audit.md`. Also remove the production-audit link from `README.md` before a public release if it remains a prompt/history artifact.

Recommended root policy: keep only `README.md`, `CHANGELOG.md`, and optionally `DEPLOYMENT.md` at the root. Move long-form security, integrator, architecture, and audit documents under `docs/`.

## Verification Performed

Command:

```bash
./mvnw -Dspring.profiles.active=test -Dtest=AbuseThrottleFailClosedTest,EmailOutboxServiceTest,OpenApiContractTest,CriticalAuditRollbackIntegrationTest test -B
```

Result: 7 tests run, 0 failures, 0 errors, 0 skipped.

Note: This focused run does not cover the filter-level fail-closed HTTP response gap identified above.
