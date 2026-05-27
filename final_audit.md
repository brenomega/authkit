# Final AuthKit Production Audit

This document consolidates the valid findings from two independent audits:

- `AUTHKIT_PRODUCTION_AUDIT.md`, the prior AI audit.
- A stricter follow-up audit performed against the repository, including source review and test execution.

This version was reassessed after Prompt 1 implementation on branch `secure-session-admin-tenant-hardening`.

## Verification

- Baseline follow-up audit: `./mvnw test -Dspring.profiles.active=test -B`
  - Result before Prompt 1: 143 tests run, 0 failures, 0 errors, 2 skipped.
- Prompt 1 targeted security tests: `./mvnw test -Dspring.profiles.active=test -Dtest=ProfileServiceTest,MfaServiceTest,PasskeyServiceTest,AdminServiceTest,OAuthProviderServiceTest -B`
  - Result: 32 tests run, 0 failures, 0 errors, 0 skipped.
- Prompt 1 full regression suite: `./mvnw test -Dspring.profiles.active=test -B`
  - Result: 158 tests run, 0 failures, 0 errors, 3 skipped.
  - Note: PostgreSQL/Testcontainers migration coverage is implemented, but skipped in this sandbox because Docker is unavailable.

## Executive Summary

Current verdict after Prompt 1: approved only with compensating controls, not approved as a broad public reference-grade authentication service yet.

Prompt 1 closed the largest production blockers: access tokens are now bound to live refresh-session state, sensitive revocation paths deny old access tokens, admin writes require current-password step-up plus MFA/passkey proof, step-up failures feed account lockout, tenant-admin boundaries are explicit, OAuth authorization codes are no longer exposed as a JSON field, confirmation tokens expire and rotate on resend, retention cleanup covers related tables, and Kubernetes JWT key delivery is consistent.

The system is materially safer, but still needs Prompt 2 and Prompt 3 before high-assurance public production. Remaining risks are abuse controls under Redis failure, endpoint-specific rate limits, JWT key rotation, CORS/gateway guarantees, worker authentication, email delivery semantics, OAuth/OIDC completeness, load evidence, distributed scheduled-job coordination, observability runbooks, supply-chain hardening, and frontend token-handling review.

Reassessed scores:

| Area | Score |
| --- | ---: |
| Production readiness | 6.8/10 |
| Security | 7.2/10 |
| Performance and scalability | 6.5/10 |
| Maintainability | 7.4/10 |
| Reference authentication model | 6.1/10 |
| Global architecture | 6.9/10 |

## Layer-by-Layer Scorecard

| Layer | Score | Verdict | Main Remaining Issue | Priority |
| --- | ---: | --- | --- | --- |
| Authentication architecture | 7.4 | Conditionally production-ready | Recovery, OAuth/OIDC, and key lifecycle still need hardening | High |
| Authorization and access control | 7.5 | Conditionally production-ready | Tenant model remains simple and should be validated for real multi-tenant use | High |
| Session, token, cookie security | 7.6 | Conditionally production-ready | JWT signing-key rotation and downstream validation contracts remain incomplete | High |
| Password and credential security | 7.2 | Conditionally production-ready | Recovery token URL exposure and breached-password screening remain | High |
| MFA, passkeys, modern auth | 7.3 | Conditionally production-ready | Admin passkey-first policy and phishing-risk documentation remain | Medium |
| API and backend security | 6.8 | Conditionally production-ready | Endpoint-specific throttling and Redis degradation policy remain | Critical |
| Frontend security | 4.5 | Not production-ready from this repo alone | Consuming frontend token storage/XSS/redirect safety not audited | High |
| Database and data model | 7.1 | Conditionally production-ready | PostgreSQL retention test must run in Docker-enabled CI; tenant model is still basic | High |
| Infrastructure, config, secrets | 6.6 | Conditionally production-ready | CORS, proxy trust, image promotion/signing, and key rotation remain | High |
| Dependency and supply chain | 6.8 | Conditionally production-ready | SBOM publication, image signing, stricter CVE gates remain | Medium |
| Observability, auditability, IR | 6.9 | Conditionally production-ready | SIEM/PagerDuty wiring and audit-failure policy remain | High |
| Performance and scalability | 6.5 | Conditionally production-ready | No load evidence for Argon2, Redis, DB pools, auth hot paths | High |
| Reliability and readiness | 6.4 | Conditionally production-ready | Email/Rabbit reliability and scheduled-job coordination remain | High |
| Testing and verification | 7.0 | Conditionally production-ready | Redis-failure, CORS, key-rotation, load, and OAuth conformance tests remain | High |
| Developer experience | 7.5 | Conditionally production-ready | Security invariants and runbooks need more complete docs | Medium |
| Compliance/privacy | 6.7 | Conditionally production-ready | DSAR/export governance and retention proof in real Postgres CI remain | High |

## Prompt 1 Completion Status

- [x] Enforce access-token session binding by validating JWT `jti` against server-side session state on authenticated requests.
- [x] Ensure logout, logout-all, password reset, account deletion, role changes, and refresh-token family compromise invalidate or deny affected access tokens.
- [x] Add tests proving stolen old access tokens fail after logout-all, password reset, account deletion, and session revocation.
- [x] Require MFA or passkey for all admin accounts before any admin write operation.
- [x] Require fresh step-up for role changes, OAuth client creation/update/disable, MFA disable, passkey disable, password change, and account deletion.
- [x] Add per-user throttling/lockout for failed step-up password and MFA attempts.
- [x] Define tenant model explicitly: global admin, tenant admin, owner, and normal user boundaries.
- [x] Replace reliance on Hibernate filters with mandatory object-level authorization checks for direct-ID lookups touched by Prompt 1.
- [x] Add tests for tenant breakout and IDOR attempts across users, sessions, passkeys, MFA credentials, OAuth clients, consents, and admin operations.
- [x] Remove raw OAuth authorization code from JSON responses.
- [x] Add OAuth tests for code replay, code leakage prevention, redirect URI exact matching, PKCE verifier validation, tenant mismatch, consent denial, and concurrent token exchange.
- [x] Add email confirmation token expiry, resend rotation, and invalidation.
- [x] Fix retention deletion with explicit cleanup/cascade/anonymization for MFA, passkeys, OAuth consents/codes, security events, consent events, and email outbox references.
- [x] Add PostgreSQL/Flyway integration tests proving deleted-account purge works with all related tables populated.
- [x] Fix K8s JWT key delivery by mounting key secrets consistently.
- [x] Replace placeholder image digest behavior with documented immutable image promotion requirements.
- [x] Review K8s trusted-origin ranges and restrict copied defaults to real reverse proxy CIDRs.

## Critical Blocking Issues

Prompt 1 resolved the original critical blockers. No remaining issue should be treated as fixed by assumption; the following items still block broad, hostile public production unless strong compensating controls exist:

- Redis-backed abuse controls still degrade to local/pod behavior during Redis outage.
- Endpoint-specific rate limiting is not complete.
- JWT signing-key rotation and emergency key revocation are not implemented.
- CORS is not explicitly enforced in-app or proven by gateway tests.
- Worker authentication uses a shared static token.
- Email delivery state does not represent provider-confirmed delivery.
- Production load, chaos, and failover evidence is still missing.
- Frontend token storage, redirect safety, and XSS posture are outside this repo and unaudited.

## High-Risk Issues

- Password reset links still carry token material in URL/query-style flows and need stricter leakage controls or a safer exchange pattern.
- OAuth/OIDC support remains minimal: no revocation endpoint, introspection, userinfo assurance, client secret rotation, refresh-token policy for clients, or conformance-style tests.
- Audit logging is strong but still needs external SIEM/alert integration and a defined fail-open/fail-closed policy for audit persistence failure.
- RabbitMQ/email retry, DLQ, provider timeout, idempotency, and delivery semantics are incomplete.
- Scheduled retention/outbox jobs need distributed execution safety across replicas.
- Argon2 settings and concurrency limits need target-hardware load testing.
- Authority/session hot paths need production-scale profiling.
- Supply-chain posture needs signed images, published SBOMs, stricter dependency gates, and release versioning beyond `0.0.1-SNAPSHOT`.

## Performance Bottlenecks and Scaling Risks

- Argon2 hashing can become CPU/memory pressure under login, step-up, password reset, and client-secret verification load.
- Per-request access-token session binding adds a Redis dependency to authenticated traffic; Redis latency and outage policy now matter more.
- Authority refresh/cache behavior improves freshness but should be profiled under high request volume.
- Rate limiting is still coarse and may under-protect high-risk endpoints while consuming shared buckets.
- Session listing and Redis key patterns need validation for users with many sessions.
- Hikari, Redis client, servlet thread, request body, and queue settings need load-backed sizing.
- Retention and outbox scheduled jobs may duplicate work across replicas without distributed locks or idempotency proof.

## Threat Model Summary

- Credential stuffing and brute force: partially mitigated by lockout and rate limits, but endpoint-specific and Redis-failure behavior remain unfinished.
- Account enumeration: registration and recovery are mostly stealthy; resend/recovery caps still need Prompt 2.
- Session theft: materially improved by session-bound access tokens; stolen tokens become invalid after session revocation, but token theft is still useful until revoked or expired.
- CSRF: refresh-cookie CSRF is present; cross-app CORS and frontend behavior still need validation.
- XSS: backend cannot prove frontend token storage safety; consuming frontend requires separate audit.
- OAuth/OIDC misuse: PKCE and code replay protections improved; provider completeness and conformance remain unfinished.
- MFA bypass: admin writes now require password step-up plus TOTP or fresh passkey; passkey-first admin policy remains.
- Privilege escalation and tenant breakout: Prompt 1 added explicit tenant-admin boundaries and negative tests; real shared-tenant modeling needs future design.
- Token leakage: access/refresh lifecycle improved; password reset URL leakage remains.
- Misconfigured CORS/proxy headers: still a deployment risk until explicit tests and gateway policy exist.
- Secret leakage/dependency compromise: production validators and CI scans help, but key rotation, signed artifacts, and stricter supply-chain gates remain.

## Three-Step Remediation Roadmap

### Prompt 1: Close Production Blockers in Auth, Admin, Tenancy, OAuth, Retention, and Deployment

Status: complete on `secure-session-admin-tenant-hardening`.

Checklist: see "Prompt 1 Completion Status" above.

### Prompt 2: Harden Abuse Controls, Recovery, Keys, Internal Auth, CORS, Email, and OAuth/OIDC

Add production-grade abuse resistance and operational security around authentication flows. Treat Redis outage, email-provider failure, token leakage, and proxy misconfiguration as expected failure modes.

- [ ] Add endpoint-specific rate limits for login, MFA login verify, passkey assertion, registration, email confirmation resend, password recovery request, password reset, OAuth authorize, OAuth token, admin writes, profile writes, MFA changes, passkey changes, and account deletion.
- [ ] Add per-account, per-email, per-tenant, per-IP, and per-device/user-agent dimensions where appropriate.
- [ ] Decide fail-open versus fail-closed behavior for Redis-backed rate limiting and lockout.
- [ ] For high-risk endpoints, fail closed or degrade to much stricter local limits when Redis is unavailable.
- [ ] Emit high-severity metrics/logs when global rate limiting or lockout degrades.
- [ ] Add runbooks and alerts for Redis fail-open/fail-closed states.
- [ ] Add per-email cooldowns and daily caps for recovery and confirmation emails.
- [ ] Move password reset token exchange away from query-string exposure where possible; otherwise add strict `Referrer-Policy`, log redaction, short TTL, one-time use, and frontend handling guidance.
- [ ] Add breached-password screening, password reuse/history policy, and optional password strength feedback.
- [ ] Implement JWT signing-key rotation with multiple published JWKS keys, active/retiring states, emergency revocation, and tests.
- [ ] Document downstream resource-server validation for issuer, audience, `kid`, algorithm, expiration, tenant, scopes, and key rotation.
- [ ] Add explicit CORS configuration or a documented gateway-only CORS policy with tests.
- [ ] Replace or harden `X-Worker-Token`: use mTLS/workload identity where possible; otherwise add rotation, scoped internal permissions, network allowlists, and audit.
- [ ] Add RabbitMQ DLQ/retry/backoff configuration for email delivery.
- [ ] Add HTTP client timeouts, idempotency strategy, provider failure handling, and delivery-state tracking for Resend.
- [ ] Ensure outbox state represents actual delivery semantics, not just successful queue publish.
- [ ] Complete OAuth/OIDC hardening: client secret rotation, revocation endpoint, introspection if needed, userinfo if advertised, complete discovery metadata, refresh-token policy if supported, and conformance-style tests.
- [ ] Make passkeys the preferred admin MFA method; keep TOTP as fallback with clear phishing-risk documentation.

### Prompt 3: Prove Scale, Reliability, Observability, Compliance, Supply Chain, and Frontend Safety

Turn the hardened implementation into a production-operable system with load evidence, runbooks, alerts, and consumer-facing contracts.

- [ ] Load-test login, refresh, MFA verify, passkey verify, OAuth token exchange, admin writes, and profile reads/writes at expected and burst traffic levels.
- [ ] Measure p50/p95/p99 latency, DB pool usage, Redis latency, CPU, memory, GC, Argon2 queueing, and error rates.
- [ ] Tune Argon2 memory/iterations/parallelism against target hardware and document the chosen threat/performance tradeoff.
- [ ] Validate Hikari pool size, Redis pool/client behavior, servlet thread limits, and request body limits under attack-like load.
- [ ] Profile `UserAuthoritiesFilter` and authority-cache behavior under high request volume.
- [ ] Replace expensive Redis/session enumeration patterns if needed for high session counts.
- [ ] Add distributed locks or idempotent coordination for scheduled retention and outbox jobs across replicas.
- [ ] Add chaos tests for Redis down, DB partial outage, RabbitMQ down, email provider down, clock skew, expired keys, and rolling deploys during key rotation.
- [ ] Expand tests to include real PostgreSQL/Flyway migrations in Docker-enabled CI, Redis failure, endpoint rate limits, CORS, ingress/proxy headers, OAuth/passkey E2E, and negative permission cases.
- [ ] Wire security events and `SECURITY_ALERT` logs to SIEM/PagerDuty or equivalent alerting.
- [ ] Define audit durability policy: when audit persistence fails, decide which flows fail closed and which continue with degraded alerting.
- [ ] Add dashboards for login failures, lockouts, MFA failures, reset requests, OAuth code failures, refresh reuse, admin actions, Redis fail-open, audit drops, email failures, and latency SLOs.
- [ ] Publish SBOM artifacts, sign container images, enforce dependency scanning for HIGH/CRITICAL issues, and run OWASP dependency-check in CI with a stricter threshold.
- [ ] Add release/versioning discipline instead of relying on `0.0.1-SNAPSHOT` for production artifacts.
- [ ] Document backup/restore, key recovery, Redis data loss behavior, DB migration rollback/forward policy, and incident response.
- [ ] Complete privacy governance: DSAR export, account deletion proof, retention schedule, PII minimization, audit trail integrity, and legal basis documentation.
- [ ] Audit the consuming frontend separately for XSS, token storage, redirect safety, CSRF assumptions, auth-state hydration, route protection, dependency risk, and secure UX.
- [ ] Produce OpenAPI/security documentation for integrators, including token claims, cookie behavior, CORS expectations, OAuth/OIDC support boundaries, and operational limits.

## Final Recommendation

Prompt 1 was effective and materially improved the project from "not approved" to "approved only with compensating controls" for controlled production or limited hostile exposure.

Do not advertise this as a reference-grade authentication model or launch it as a broad public auth platform until Prompts 2 and 3 are complete, verified in CI with Docker-enabled PostgreSQL/Redis coverage, and supported by operational runbooks and monitoring.
