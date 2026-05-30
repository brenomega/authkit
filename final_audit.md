# Final AuthKit Production Audit

This document consolidates the valid findings from two independent audits:

- `AUTHKIT_PRODUCTION_AUDIT.md`, the prior AI audit.
- A stricter follow-up audit performed against the repository, including source review and test execution.

This version was reassessed after Prompt 2 implementation on branch `auth-abuse-recovery-key-hardening`.

## Verification

- Baseline follow-up audit: `./mvnw test -Dspring.profiles.active=test -B`
  - Result before Prompt 1: 143 tests run, 0 failures, 0 errors, 2 skipped.
- Prompt 1 targeted security tests: `./mvnw test -Dspring.profiles.active=test -Dtest=ProfileServiceTest,MfaServiceTest,PasskeyServiceTest,AdminServiceTest,OAuthProviderServiceTest -B`
  - Result: 32 tests run, 0 failures, 0 errors, 0 skipped.
- Prompt 1 full regression suite: `./mvnw test -Dspring.profiles.active=test -B`
  - Result: 158 tests run, 0 failures, 0 errors, 3 skipped.
- Prompt 2 targeted security/reliability tests: `./mvnw test -Dspring.profiles.active=test -Dtest=SecurityIntegrationTest,ProductionConfigValidatorTest,JwtKeyServiceTest,PasswordPolicyServiceTest,OAuthProviderServiceTest,EmailOutboxProcessorTest,PasswordRecoveryServiceTest,RegistrationServiceTest,AuthServiceTest,ProfileServiceTest,MfaServiceTest,AccountLifecycleServiceTest,ActuatorSecurityIntegrationTest -B`
  - Result: 78 tests run, 0 failures, 0 errors, 0 skipped.
- Prompt 2 full regression suite: `./mvnw clean test -Dspring.profiles.active=test -B`
  - Result: 165 tests run, 0 failures, 0 errors, 3 skipped.
  - Note: PostgreSQL/Testcontainers migration coverage exists, but remains skipped in this sandbox when Docker is unavailable.

## Executive Summary

Current verdict after Prompt 2: conditionally production-ready for controlled production with strong operational controls; still not approved as a broad public, reference-grade authentication service until Prompt 3 evidence exists.

Prompt 1 closed the original production blockers: live session-bound access tokens, sensitive revocation paths, admin step-up, tenant-admin boundaries, OAuth code leakage, confirmation token lifecycle, retention cleanup, and Kubernetes key delivery.

Prompt 2 materially improved abuse resistance and operational hardening: endpoint/account throttles now cover high-risk auth flows with strict local fallback on Redis failure, recovery and confirmation emails have cooldown/daily caps, password reset links no longer place token material in query strings, password policy/history prevents weak and reused passwords, JWT key rotation/revocation is implemented, CORS is explicit and production-validated, worker-token access is network-bound and rotatable, RabbitMQ/Resend email delivery now has DLQ/retry/idempotency/provider-state tracking, and OAuth/OIDC now includes client secret rotation, revocation, introspection, userinfo, discovery metadata, and tests.

Remaining risks split into two buckets: **Prompt 2.5 (implementable now)** — token-type API boundaries, distributed scheduler locks, audit fail-closed policy, session-list caps, OpenAPI/integrator docs, alert rules as code, optional HIBP/fail-closed abuse flag; **Prompt 3 (proof)** — load/chaos evidence, live SIEM, signed releases, frontend audit, and hardware-tuned performance.

Reassessed scores:

| Area | Score |
| --- | ---: |
| Production readiness | 7.6/10 |
| Security | 7.9/10 |
| Performance and scalability | 7.1/10 |
| Maintainability | 7.8/10 |
| Reference authentication model | 7.0/10 |
| Global architecture | 7.7/10 |

## Layer-by-Layer Scorecard

| Layer | Score | Verdict | Main Remaining Issue | Priority |
| --- | ---: | --- | --- | --- |
| Authentication architecture | 8.0 | Conditionally production-ready | Needs load/chaos evidence and tighter OAuth conformance proof | High |
| Authorization and access control | 7.7 | Conditionally production-ready | Tenant model remains simple and should be validated for real multi-tenant SaaS use | High |
| Session, token, cookie security | 8.0 | Conditionally production-ready | Downstream revocation/key-rotation behavior must be proven in deployed consumers | High |
| Password and credential security | 8.0 | Conditionally production-ready | Breached-password screening is local/static, not an external corpus/service | Medium |
| MFA, passkeys, modern auth | 7.8 | Conditionally production-ready | Passkeys are preferred for admins, but phishing-resistant enforcement is not mandatory | Medium |
| API and backend security | 7.9 | Conditionally production-ready | Redis-degraded protection is stricter local fallback, not true global enforcement | High |
| Frontend security | 4.5 | Not production-ready from this repo alone | Consuming frontend token storage/XSS/redirect safety not audited | High |
| Database and data model | 7.6 | Conditionally production-ready | Scheduled jobs need distributed coordination and Docker-backed migration proof in CI | High |
| Infrastructure, config, secrets | 7.7 | Conditionally production-ready | mTLS/workload identity, signed images, and live gateway validation remain | High |
| Dependency and supply chain | 6.8 | Conditionally production-ready | SBOM publication, image signing, stricter CVE gates remain | Medium |
| Observability, auditability, IR | 7.3 | Conditionally production-ready | SIEM/PagerDuty wiring and audit-failure policy remain | High |
| Performance and scalability | 7.1 | Conditionally production-ready | No load evidence for Argon2, Redis, DB pools, queues, and auth hot paths | High |
| Reliability and readiness | 7.2 | Conditionally production-ready | Chaos tests remain; scheduled jobs need distributed coordination (Prompt 2.5) | High |
| Testing and verification | 7.5 | Conditionally production-ready | Load, Redis-failure, CORS/gateway, OAuth/passkey E2E, and real Postgres CI breadth remain | High |
| Developer experience | 7.8 | Conditionally production-ready | Security docs improved; OpenAPI/integrator docs still need completion | Medium |
| Compliance/privacy | 7.0 | Conditionally production-ready | DSAR/export governance and retention proof in real production processes remain | High |

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

## Prompt 2 Completion Status

- [x] Add endpoint-specific rate limits for login, MFA login verify, passkey assertion, registration, email confirmation resend, password recovery request, password reset, OAuth authorize, OAuth token, admin writes, profile writes, MFA changes, passkey changes, and account deletion.
- [x] Add per-account, per-email, per-tenant, per-IP, and per-device/user-agent dimensions where appropriate.
- [x] Decide fail-open versus fail-closed behavior for Redis-backed rate limiting and lockout.
- [x] For high-risk endpoints, fail closed or degrade to much stricter local limits when Redis is unavailable.
- [x] Emit high-severity metrics/logs when global rate limiting or lockout degrades.
- [x] Add runbooks and alerts for Redis fail-open/fail-closed states.
- [x] Add per-email cooldowns and daily caps for recovery and confirmation emails.
- [x] Move password reset token exchange away from query-string exposure where possible; otherwise add strict `Referrer-Policy`, log redaction, short TTL, one-time use, and frontend handling guidance.
- [x] Add breached-password screening, password reuse/history policy, and optional password strength feedback.
- [x] Implement JWT signing-key rotation with multiple published JWKS keys, active/retiring states, emergency revocation, and tests.
- [x] Document downstream resource-server validation for issuer, audience, `kid`, algorithm, expiration, tenant, scopes, and key rotation.
- [x] Add explicit CORS configuration or a documented gateway-only CORS policy with tests.
- [x] Replace or harden `X-Worker-Token`: use mTLS/workload identity where possible; otherwise add rotation, scoped internal permissions, network allowlists, and audit.
- [x] Add RabbitMQ DLQ/retry/backoff configuration for email delivery.
- [x] Add HTTP client timeouts, idempotency strategy, provider failure handling, and delivery-state tracking for Resend.
- [x] Ensure outbox state represents actual delivery semantics, not just successful queue publish.
- [x] Complete OAuth/OIDC hardening: client secret rotation, revocation endpoint, introspection if needed, userinfo if advertised, complete discovery metadata, refresh-token policy if supported, and conformance-style tests.
- [x] Make passkeys the preferred admin MFA method; keep TOTP as fallback with clear phishing-risk documentation.

## Critical Blocking Issues

No original critical authentication bypass or token-lifecycle blocker remains open after Prompt 2.

**Address in Prompt 2.5 before multi-replica production:** distributed job coordination, OAuth-vs-first-party token enforcement on user APIs, audit durability policy, integrator contracts (OpenAPI), and observability artifacts (alert rules).

**Address in Prompt 3 before broad/medium SaaS marketing:** load/soak/burst proof, chaos tests, live SIEM/drills, signed images, frontend audit (out of repo), and Argon2/pool tuning from measured hardware.

## High-Risk Issues

- Redis degraded mode is safer than before but remains per-node local enforcement; high-risk endpoints should also be backed by WAF/ingress controls and alerting.
- OAuth/OIDC is much stronger but still needs conformance-style interoperability tests with real clients and downstream resource servers.
- JWT key rotation is implemented in AuthKit, but consumers must prove JWKS cache refresh and revoked-`kid` handling.
- RabbitMQ/Resend delivery state is improved, but queue/DLQ behavior needs chaos tests for broker down, provider down, and duplicate provider responses.
- Audit logging is strong but still needs external SIEM/alert integration and a defined fail-open/fail-closed policy for audit persistence failure.
- Argon2 settings and concurrency limits need target-hardware load testing.
- Authority/session hot paths need production-scale profiling.

## Performance Bottlenecks and Scaling Risks

- Argon2 hashing can become CPU/memory pressure under login, step-up, password reset, registration, and client-secret verification load.
- Per-request access-token session binding adds Redis latency to authenticated traffic; Redis sizing and locality are now critical.
- Endpoint abuse throttles add Redis/Caffeine lookups to public hot paths; degraded local limits avoid total loss of control but can amplify across many pods.
- Authority refresh/cache behavior improves freshness but should be profiled under high request volume.
- Session listing and Redis key patterns need validation for users with many sessions.
- Hikari, Redis client, servlet thread, request body, RabbitMQ listener, and queue settings need load-backed sizing.
- Retention and outbox scheduled jobs may duplicate work across replicas without distributed locks or idempotency proof.

## Threat Model Summary

- Credential stuffing and brute force: now covered by endpoint, IP, email/account, device, lockout, and step-up throttles, but distributed enforcement still depends on Redis health.
- Account enumeration: registration and recovery remain stealthy; resend/recovery email cooldowns and daily caps reduce mailbox abuse.
- Session theft: session-bound access tokens invalidate after revocation events; stolen access tokens remain useful until expiry or revocation.
- CSRF: refresh-cookie CSRF is present; CORS is explicit and tested, but consuming frontends still need separate validation.
- XSS: backend cannot prove frontend token storage safety; consuming frontend requires separate audit.
- OAuth/OIDC misuse: PKCE, code replay protections, exact redirects, revocation, introspection, userinfo, and discovery are implemented; real conformance testing remains.
- MFA bypass: admin writes require password step-up plus MFA/passkey proof; passkeys are preferred but not mandatory.
- Privilege escalation and tenant breakout: explicit tenant-admin boundaries and negative tests exist; real shared-tenant modeling needs future design if AuthKit becomes a SaaS tenant authority.
- Token leakage: password reset tokens moved to URL fragments and request bodies; logs redact sensitive fields and reset tokens remain short-lived and one-time.
- Misconfigured CORS/proxy headers: production validators reject unsafe CORS; gateway/ingress behavior still needs deployment validation.
- Secret leakage/dependency compromise: production validators and CI scans help, but key rotation drills, signed artifacts, and stricter supply-chain gates remain.

## Product Target (Post Prompt 3)

AuthKit should be the **primary auth boundary** for **small SaaS** (hundreds of users) and scale horizontally to **medium SaaS** (tens of thousands), deployable as:

1. **Standalone auth API** in an existing production mesh.
2. **Embedded module** in a monolith sharing Postgres/Redis.
3. **Monolithic SaaS core** with AuthKit packages/controllers co-located.

Prompt 2.5 closes implementable gaps before expensive proof work. Prompt 3 supplies **evidence** (load, chaos, live ops) to reach **8+ production readiness** for controlled and medium-scale production.

## Four-Step Remediation Roadmap

### Prompt 1: Close Production Blockers in Auth, Admin, Tenancy, OAuth, Retention, and Deployment

Status: complete on `secure-session-admin-tenant-hardening`.

Checklist: see "Prompt 1 Completion Status" above.

### Prompt 2: Harden Abuse Controls, Recovery, Keys, Internal Auth, CORS, Email, and OAuth/OIDC

Status: complete on `auth-abuse-recovery-key-hardening`.

Checklist: see "Prompt 2 Completion Status" above.

### Prompt 2.5: Pre-Proof Hardening — Implementable Gaps Before Load/Ops Evidence

**Goal:** Reach **~7.9–8.2 production readiness** and **~8.0–8.3 security** in code/docs/CI without full load suites or live SIEM. Single implementation pass; defer proof-only work to Prompt 3.

**Branch suggestion:** `auth-preproof-hardening`

#### A. Token model and API boundaries (security correctness)

- [ ] Enforce **two token classes** in `UserAuthoritiesFilter` (or dedicated filter): AuthKit session-bound access tokens (`aud` = `AUTH_JWT_AUDIENCE`) require `tokenStorage.isSessionActive`; **OAuth client-audience** tokens must not call `/api/v1/users/**` or other first-party user APIs (reject with 401/403, not silent session miss).
- [ ] Document in `INTEGRATOR.md`: first-party vs OAuth token usage, claims (`tenant_id`, `amr`, `mfa`, `client_id`, `scope`), cookie+CSRF for refresh, fragment-based reset flow.
- [ ] Add integration tests: OAuth-issued token rejected on `/api/v1/users/me`; session-bound token rejected after `logout-all` / password reset / session revoke.

#### B. Reliability on multiple replicas (small/medium SaaS baseline)

- [ ] Add **distributed locks** (ShedLock + JDBC/Redis) for `EmailOutboxProcessor` and `DataRetentionService` scheduled jobs; document single-replica fallback for dev.
- [ ] Make retention/outbox processing **idempotent** under duplicate lock loss (safe replays, no double-send email).
- [ ] Cap or paginate `tokenStorage.listSessions` (avoid unbounded `HKEYS` on large session sets); add test for many-session user.

#### C. Audit and observability as code (not live SIEM yet)

- [ ] Implement **audit durability policy**: critical events (login failure lockout, admin actions, refresh reuse, MFA disable, account delete) **fail closed** or queue with synchronous fallback when DB audit write fails; non-critical events degrade with `security.audit.dropped` metric + `SECURITY_ALERT`.
- [ ] Add `observability/prometheus-alerts.yml` (or equivalent) for: Redis abuse/lockout degraded, refresh family reuse, worker auth denied, email outbox failures, Argon2 capacity exceeded, audit drops.
- [ ] Add `observability/grafana-dashboard.json` skeleton or documented panel list matching DEPLOYMENT runbooks.

#### D. Abuse controls — close Prompt 2 partials

- [ ] Add optional `AUTH_ABUSE_FAIL_CLOSED_HIGH_RISK` (default `false`): when Redis Layer 2 unavailable, return 503 on login/MFA verify/recovery/register/OAuth token instead of only strict local limits (document tradeoff).
- [ ] Optional **HIBP k-anonymity** breached-password check behind `AUTH_PASSWORD_HIBP_ENABLED` (fail open on API timeout).
- [ ] Expand OAuth/passkey **negative** integration tests (wrong `aud`, expired code, introspection inactive token); no full external conformance suite yet.

#### E. Integrator and deployment contracts (DX for standalone / embedded / monolith)

- [ ] Publish **OpenAPI 3** for public `/api/v1/**`, auth, and OAuth endpoints; link from README.
- [ ] Add `docs/DEPLOYMENT_MODES.md`: standalone (2+ pods + Redis + Postgres + Rabbit), embedded (shared infra), monolith (disable origin firewall / adjust pools).
- [ ] Add **sizing defaults** in DEPLOYMENT for ~500, ~5k, ~50k users (replicas, Hikari, Redis memory, Argon2 concurrency).
- [ ] Add **resource-server checklist** (JWKS refresh, `kid` revocation, audience, tenant claim) with minimal Java/Spring example or pseudo-config.

#### F. CI and supply-chain prep (lightweight, pre–Prompt 3)

- [ ] CI: upload CycloneDX SBOM artifact from existing plugin; fail on new CRITICAL unfixed CVEs (Trivy already runs).
- [ ] CI: run `PostgresMigrationTest` / Testcontainers when Docker available (separate job, not blocking sandbox).
- [ ] Introduce **release version** discipline (`pom.xml` version + `CHANGELOG.md` template); keep SNAPSHOT for dev only.
- [ ] Fix audit doc drift: scorecard reliability row, Prompt 2 “mTLS where possible” → **network-bound worker token** (mTLS remains Prompt 3 stretch).

#### Explicitly out of scope for Prompt 2.5 (Prompt 3)

- k6/Gatling load and soak reports; Argon2 tuning from measured hardware.
- Live SIEM/PagerDuty wiring and incident drills.
- Container image signing (cosign) and promotion gates.
- Full OIDC conformance with external clients.
- Frontend XSS/token-storage audit (separate repo).
- Worker **mTLS** / SPIFFE (optional Prompt 3 if mesh exists).

**Expected scores after Prompt 2.5 (strict):** production **7.9–8.2**, security **8.0–8.3**, performance **7.2–7.4** (prep only), reference model **7.2–7.5**.

### Prompt 3: Prove Scale, Reliability, Observability, Compliance, Supply Chain, and Frontend Safety

Turn the hardened implementation into a **production-operable** system with measured SLOs and live ops proof. Target: **8.2–8.5 production readiness** for small/medium SaaS as main auth entry.

- [ ] Load-test login, refresh, MFA verify, passkey verify, OAuth token exchange, admin writes, profile reads/writes at expected and **burst** traffic (document scenarios for ~500 and ~50k user bases).
- [ ] Measure p50/p95/p99 latency, DB pool, Redis, CPU, memory, GC, Argon2 queueing, error rates; tune `SECURITY_ARGON2_*`, Hikari, listener concurrency from results.
- [ ] Profile `UserAuthoritiesFilter`, session binding, and authority cache under sustained authenticated RPS.
- [ ] Chaos tests: Redis down, DB read-only, RabbitMQ down, Resend 5xx/timeout, clock skew, key rotation during rolling deploy, duplicate email provider callbacks.
- [ ] Expand CI: mandatory Postgres/Flyway job with Docker; Redis-failure and fail-closed abuse tests; CORS/gateway smoke; OAuth/passkey E2E where feasible.
- [ ] Wire `SECURITY_ALERT` + security metrics to SIEM/PagerDuty; run one tabletop drill using DEPLOYMENT runbooks.
- [ ] Sign container images; enforce SBOM + dependency-check gates on release tags.
- [ ] Document backup/restore, Redis data-loss behavior, migration rollback policy, DR for keys and sessions.
- [ ] Privacy/ops proof: DSAR export drill, deletion + retention verification in staging, legal-basis doc pack.
- [ ] **Frontend security audit** (consumer app): XSS, token storage, redirects, CSRF header echo, route guards.
- [ ] Optional: worker mTLS in Kubernetes; external OIDC conformance log.

## Reference Authentication Model Assessment

AuthKit is now substantially closer to a reference-grade architecture: it has strong token/session lifecycle controls, explicit admin step-up, modern passkey support, OAuth/OIDC provider hardening, privacy-safe audit trails, outbox-backed email, key rotation, and layered abuse controls. What prevents reference-grade status is not one obvious missing auth feature; it is the lack of operational proof. A reference model needs repeatable load results, chaos evidence, deployed observability, CI migration coverage on real infrastructure, frontend safety validation, and supply-chain release discipline.

## Risk Acceptance Notes

- Accepting production without Prompt 3 means accepting unknown latency/error behavior under credential stuffing, Redis latency, DB pool pressure, and email-provider failures.
- Accepting per-node degraded throttles during Redis outages means a large replica count can multiply allowed attack volume unless ingress/WAF controls also enforce limits.
- Accepting unaudited frontend integration means XSS or unsafe token storage could defeat otherwise strong backend controls.
- Accepting unsigned images and weak release versioning increases the chance of supply-chain ambiguity during incident response.

## Final Recommendation

Prompt 2 was effective and materially improved AuthKit from "approved only with compensating controls for limited exposure" to "conditionally production-ready for controlled production."

**After Prompt 2.5:** approved for **small/medium SaaS** as primary auth API with edge compensating controls (WAF, network policies) and documented integrator contracts.

**After Prompt 3:** approved for **medium-scale horizontal production** (target **8.2–8.5** production readiness) as standalone service, embedded module, or monolith auth core — still not “reference-grade 9+” without frontend proof and operational track record.

Current strict recommendation: approved only with compensating controls until Prompt 2.5 completes; Prompt 3 required for measured-scale confidence.
