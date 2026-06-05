# Final AuthKit Production Audit

This document consolidates the valid findings from two independent audits:

- `AUTHKIT_PRODUCTION_AUDIT.md`, the prior AI audit.
- A stricter follow-up audit performed against the repository, including source review and test execution.

This version was reassessed after Prompt 2.5 implementation on branch `auth-preproof-hardening`.

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
- Prompt 2.5 focused security/reliability proof: token-class API rejection, runtime/startup abuse fail-closed behavior, critical-audit rollback, repeat-safe retention, provider idempotency, HIBP, outbox terminal state, session pagination, production validation, and OpenAPI contract tests.
  - Result: all focused non-Docker tests passed; Docker-backed PostgreSQL/Redis tests are present but skipped in this restricted sandbox.
- Prompt 2.5 full regression/package suite: `./mvnw clean verify -Dspring.profiles.active=test -B`
  - Result: 202 tests run, 0 failures, 0 errors, 5 skipped; the application JAR, embedded CycloneDX JSON SBOM, and CI publication JSON/XML SBOMs were generated successfully.
- Prompt 2.5 OAuth boundary/negative suite after final additions: `OAuthProviderServiceTest`
  - Result: 7 tests run, 0 failures, 0 errors, 0 skipped.

Docker-backed PostgreSQL migration/ShedLock and Redis HSCAN tests are committed and have dedicated CI execution, but local proof remains unavailable in this sandbox because access to the Docker socket is denied.

## Executive Summary

Current verdict after Prompt 2.5: conditionally production-ready for controlled small/medium production with edge and operational controls. It is still not approved as a broad, unmeasured, reference-grade authentication service until Prompt 3 evidence exists.

Prompt 1 closed the original production blockers: live session-bound access tokens, sensitive revocation paths, admin step-up, tenant-admin boundaries, OAuth code leakage, confirmation token lifecycle, retention cleanup, and Kubernetes key delivery.

Prompt 2 materially improved abuse resistance and operational hardening: endpoint/account throttles cover high-risk auth flows, recovery and confirmation emails have cooldown/daily caps, reset links avoid query-token exposure, password history is enforced, JWT rotation/revocation is implemented, CORS is production-validated, worker-token access is network-bound and rotatable, email delivery is outbox-backed, and OAuth/OIDC includes revocation, introspection, userinfo, and discovery metadata.

Prompt 2.5 closed the remaining implementable pre-proof gaps: explicit JWT classes and API boundaries, PostgreSQL-backed scheduler locking, conditional/idempotent outbox transitions, terminal email state, bounded HSCAN session pagination, critical-audit rollback, optional HIBP and high-risk abuse fail-closed behavior, alert/dashboard artifacts, OpenAPI drift testing, integrator/deployment contracts, SBOM publication, PostgreSQL migration CI, and release-version discipline.

Remaining risk is now primarily **Prompt 3 proof and operations**: measured load/soak/chaos evidence, live SIEM and incident drills, signed releases, frontend integration audit, external OIDC interoperability evidence, backup/restore drills, and hardware-tuned pool/Argon2 settings.

Reassessed scores:

| Area | Score |
| --- | ---: |
| Production readiness | 8.1/10 |
| Security | 8.2/10 |
| Performance and scalability | 7.4/10 |
| Maintainability | 8.3/10 |
| Reference authentication model | 7.5/10 |
| Global architecture | 8.0/10 |

## Layer-by-Layer Scorecard

| Layer | Score | Verdict | Main Remaining Issue | Priority |
| --- | ---: | --- | --- | --- |
| Authentication architecture | 8.3 | Conditionally production-ready | External interoperability, load, and chaos evidence remain | High |
| Authorization and access control | 7.8 | Conditionally production-ready | Tenant model remains simple and needs validation against the final SaaS tenancy model | High |
| Session, token, cookie security | 8.5 | Production-ready | Deployed consumers must prove JWKS refresh and emergency revoked-`kid` handling | High |
| Password and credential security | 8.4 | Production-ready | HIBP is correctly opt-in/fail-open; provider availability and policy effectiveness need operational measurement | Medium |
| MFA, passkeys, modern auth | 7.9 | Conditionally production-ready | Phishing-resistant MFA is preferred but not mandatory for every privileged identity | Medium |
| API and backend security | 8.4 | Production-ready | WAF/gateway controls and Redis outage behavior still require deployed validation | High |
| Frontend security | 4.5 | Not production-ready from this repo alone | Consuming frontend token storage/XSS/redirect safety not audited | High |
| Database and data model | 8.2 | Production-ready | Restore drills and production migration rehearsal remain | High |
| Infrastructure, config, secrets | 8.1 | Conditionally production-ready | Workload mTLS, signed images, and live gateway validation remain | High |
| Dependency and supply chain | 7.7 | Conditionally production-ready | Image signing, provenance, and release promotion gates remain | Medium |
| Observability, auditability, IR | 8.0 | Conditionally production-ready | Live SIEM/PagerDuty wiring and incident drills remain | High |
| Performance and scalability | 7.4 | Conditionally production-ready | No measured load evidence for Argon2, Redis, DB pools, queues, or auth hot paths | High |
| Reliability and readiness | 8.1 | Conditionally production-ready | Multi-dependency chaos and restore evidence remain | High |
| Testing and verification | 8.2 | Conditionally production-ready | Docker tests require CI proof; load, chaos, frontend, and external OIDC suites remain | High |
| Developer experience | 8.5 | Production-ready | Keep OpenAPI and integration guidance synchronized as contracts evolve | Medium |
| Compliance/privacy | 7.5 | Conditionally production-ready | Staging DSAR/deletion/retention and legal-process evidence remain | High |

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
- [x] Replace or harden `X-Worker-Token` with a rotatable **network-bound worker token**, scoped internal permissions, network allowlists, and audit. Workload mTLS/SPIFFE remains Prompt 3.
- [x] Add RabbitMQ DLQ/retry/backoff configuration for email delivery.
- [x] Add HTTP client timeouts, idempotency strategy, provider failure handling, and delivery-state tracking for Resend.
- [x] Ensure outbox state represents actual delivery semantics, not just successful queue publish.
- [x] Complete OAuth/OIDC hardening: client secret rotation, revocation endpoint, introspection if needed, userinfo if advertised, complete discovery metadata, refresh-token policy if supported, and conformance-style tests.
- [x] Make passkeys the preferred admin MFA method; keep TOTP as fallback with clear phishing-risk documentation.

## Critical Blocking Issues

No known code-level critical authentication bypass, token-lifecycle, scheduler-coordination, audit-durability, or unbounded session-list blocker remains open after Prompt 2.5.

**Prompt 3 remains a release-scope blocker for broad or high-confidence scale claims:** load/soak/burst proof, dependency chaos, live SIEM/drills, signed images, frontend audit, backup/restore drills, external OIDC interoperability, and hardware-derived Argon2/pool tuning.

## High-Risk Issues

- The high-risk Redis fail-closed option defaults to `false`; deployments accepting local degraded throttles still need WAF/ingress controls and alerts.
- OAuth/OIDC token classes are now isolated, but external interoperability/conformance with real clients and downstream resource servers remains unproven.
- JWT key rotation is implemented in AuthKit, but consumers must prove JWKS cache refresh and revoked-`kid` handling.
- RabbitMQ/Resend state transitions are idempotent and bounded, but queue/DLQ behavior still needs broker/provider chaos evidence.
- Critical audit events fail closed transactionally and noncritical drops are metered; external SIEM/alert delivery and incident response remain unproven.
- Argon2 settings and concurrency limits need target-hardware load testing.
- Authority/session hot paths need production-scale profiling.
- Container images remain unsigned and release provenance/promotion controls are not yet implemented.

## Performance Bottlenecks and Scaling Risks

- Argon2 hashing can become CPU/memory pressure under login, step-up, password reset, registration, and client-secret verification load.
- Per-request access-token session binding adds Redis latency to authenticated traffic; Redis sizing and locality are now critical.
- Endpoint abuse throttles add Redis/Caffeine lookups to public hot paths; degraded local limits avoid total loss of control but can amplify across many pods.
- Authority refresh/cache behavior improves freshness but should be profiled under high request volume.
- Session listing is bounded with HSCAN and opaque cursor state, but latency and cursor-key volume still need production-scale measurement.
- Hikari, Redis client, servlet thread, request body, RabbitMQ listener, and queue settings need load-backed sizing.
- Scheduler locking and conditional outbox transitions remove known duplicate-work correctness gaps; lock contention and failure recovery still need chaos/soak evidence.

## Threat Model Summary

- Credential stuffing and brute force: covered by endpoint, IP, email/account, device, lockout, and step-up throttles; deployments may opt into opaque 503 fail-closed behavior when Redis is unavailable.
- Account enumeration: registration and recovery remain stealthy; resend/recovery email cooldowns and daily caps reduce mailbox abuse.
- Session theft: session-bound access tokens invalidate after revocation events; stolen access tokens remain useful until expiry or revocation.
- CSRF: refresh-cookie CSRF is present; CORS is explicit and tested, but consuming frontends still need separate validation.
- XSS: backend cannot prove frontend token storage safety; consuming frontend requires separate audit.
- OAuth/OIDC misuse: explicit access/ID token classes, PKCE, expiry/replay protections, exact redirects, revocation, introspection, userinfo, and discovery are implemented; real conformance testing remains.
- MFA bypass: admin writes require password step-up plus MFA/passkey proof; passkeys are preferred but not mandatory.
- Privilege escalation and tenant breakout: explicit tenant-admin boundaries and negative tests exist; real shared-tenant modeling needs future design if AuthKit becomes a SaaS tenant authority.
- Token leakage: password reset tokens use URL fragments and request bodies; sensitive framework body logging is pinned off, application logs redact secrets, and reset tokens remain short-lived and one-time.
- Misconfigured CORS/proxy headers: production validators reject unsafe CORS; gateway/ingress behavior still needs deployment validation.
- Secret leakage/dependency compromise: production validators and CI scans help, but key rotation drills, signed artifacts, and stricter supply-chain gates remain.

## Product Target (Post Prompt 3)

AuthKit should be the **primary auth boundary** for **small SaaS** (hundreds of users) and scale horizontally to **medium SaaS** (tens of thousands), deployable as:

1. **Standalone auth API** in an existing production mesh.
2. **Embedded module** in a monolith sharing Postgres/Redis.
3. **Monolithic SaaS core** with AuthKit packages/controllers co-located.

Prompt 2.5 has closed the implementable pre-proof gaps. Prompt 3 now supplies **evidence** (load, chaos, live ops) for higher-confidence medium-scale production claims.

## Remediation Roadmap

### Prompt 1: Close Production Blockers in Auth, Admin, Tenancy, OAuth, Retention, and Deployment

Status: complete on `secure-session-admin-tenant-hardening`.

Checklist: see "Prompt 1 Completion Status" above.

### Prompt 2: Harden Abuse Controls, Recovery, Keys, Internal Auth, CORS, Email, and OAuth/OIDC

Status: complete on `auth-abuse-recovery-key-hardening`.

Checklist: see "Prompt 2 Completion Status" above.

### Prompt 2.5: Pre-Proof Hardening — Implementable Gaps Before Load/Ops Evidence

**Goal:** Reach **~7.9–8.2 production readiness** and **~8.0–8.3 security** in code/docs/CI without full load suites or live SIEM. Single implementation pass; defer proof-only work to Prompt 3.

Status: complete on `auth-preproof-hardening`.

#### A. Token model and API boundaries (security correctness)

- [x] Enforce explicit first-party access, OAuth access, and ID token classes. First-party APIs require configured audience plus active Redis session; OAuth and ID tokens are rejected before authority/session lookup. Legacy compatibility is claim/audience constrained.
- [x] Document first-party vs OAuth token usage, claims, refresh cookie/CSRF, reset fragments, JWKS refresh, audience, tenant, and scope validation in `INTEGRATOR.md`.
- [x] Prove OAuth access and ID tokens fail on `/api/v1/users/me`; prove first-party tokens fail after logout-all, password reset, and session revocation.

#### B. Reliability on multiple replicas (small/medium SaaS baseline)

- [x] Add ShedLock 7.7.0 with PostgreSQL `usingDbTime()` for email polling and retention, bounded lock durations, production validation, Flyway V13, and documented single-instance dev/test fallback.
- [x] Make retention and outbox replay-safe with bounded batch deletes, conditional state transitions, stable Resend idempotency keys, maximum 10 attempts, and terminal `DEAD` state.
- [x] Replace session-list `HKEYS` with bounded `HSCAN` pages (`limit` 1..100), opaque user-bound five-minute cursors, per-user throttle, and hundreds-of-sessions container coverage.

#### C. Audit and observability as code (not live SIEM yet)

- [x] Persist critical lockout/admin/refresh-reuse/MFA-disable/deletion events synchronously; opaque 503 rolls back active database-backed transactional mutations, while already-applied Redis/local security state may remain applied as deliberate fail-closed behavior. Noncritical failures emit `security.audit.dropped` and `SECURITY_ALERT` without failing the operation.
- [x] Complete `k8s/06-prometheus-rules.yaml` for Redis degradation, refresh reuse, worker denial, email retry/dead state, Argon2 saturation, audit drops/fail-closed events, HIBP, abuse fail-closed, and scheduler failures.
- [x] Add `observability/grafana-dashboard.json` panels for security, dependencies, HTTP, Hikari, JVM, outbox, and schedulers.

#### D. Abuse controls — close Prompt 2 partials

- [x] Add optional `AUTH_ABUSE_FAIL_CLOSED_HIGH_RISK=false`; enabled mode returns opaque 503 for high-risk auth flows on startup/runtime Redis loss and emits metrics.
- [x] Add optional HIBP k-anonymity checking with five-character SHA-1 prefixes, padded responses, bounded caching/timeouts, breached-password rejection, and metric-backed fail-open degradation.
- [x] Expand negative coverage for wrong audience/token class, expired authorization code, inactive/revoked introspection, invalid passkey ceremony, and passkey ownership bypass.

#### E. Integrator and deployment contracts (DX for standalone / embedded / monolith)

- [x] Publish static OpenAPI 3 in `docs/openapi.yaml`, link it from `README.md`, and enforce controller-operation parity with `swagger-parser-v3:2.1.35` in tests; no runtime documentation endpoint is exposed.
- [x] Add `docs/DEPLOYMENT_MODES.md` for standalone, embedded, and monolith ownership boundaries plus queue/direct email requirements.
- [x] Add explicitly unproven conservative starting-size tables for approximately 500, 5,000, and 50,000 users, including Hikari/Redis/Argon2 guidance.
- [x] Add the JWKS/`kid`/audience/tenant/scope resource-server checklist and Spring example to `INTEGRATOR.md`.

#### F. CI and supply-chain prep (lightweight, pre–Prompt 3)

- [x] Upload CycloneDX JSON/XML SBOM artifacts with SHA-pinned `upload-artifact`; preserve the stricter Trivy HIGH/CRITICAL fixed-vulnerability gates.
- [x] Add a dedicated Docker-backed PostgreSQL Flyway migration/ShedLock CI job.
- [x] Adopt Maven CI-friendly `revision`/`changelist`, default development `-SNAPSHOT`, release changelist clearing, `CHANGELOG.md`, and release instructions.
- [x] Correct audit wording to **network-bound worker token**; mTLS/SPIFFE remains Prompt 3.

#### Explicitly out of scope for Prompt 2.5 (Prompt 3)

- k6/Gatling load and soak reports; Argon2 tuning from measured hardware.
- Live SIEM/PagerDuty wiring and incident drills.
- Container image signing (cosign) and promotion gates.
- Full OIDC conformance with external clients.
- Frontend XSS/token-storage audit (separate repo).
- Worker **mTLS** / SPIFFE (optional Prompt 3 if mesh exists).

**Verified scores after Prompt 2.5 (strict):** production **8.1**, security **8.2**, performance **7.4** (pre-proof), reference model **7.5**.

### Prompt 3: Prove Scale, Reliability, Observability, Compliance, Supply Chain, and Frontend Safety

Turn the hardened implementation into a **production-operable** system with measured SLOs and live ops proof. Target: **8.2–8.5 production readiness** for small/medium SaaS as main auth entry.

- [ ] Load-test login, refresh, MFA verify, passkey verify, OAuth token exchange, admin writes, profile reads/writes at expected and **burst** traffic (document scenarios for ~500 and ~50k user bases).
- [ ] Measure p50/p95/p99 latency, DB pool, Redis, CPU, memory, GC, Argon2 queueing, error rates; tune `SECURITY_ARGON2_*`, Hikari, listener concurrency from results.
- [ ] Profile `UserAuthoritiesFilter`, session binding, and authority cache under sustained authenticated RPS.
- [ ] Chaos tests: Redis down, DB read-only, RabbitMQ down, Resend 5xx/timeout, clock skew, key rotation during rolling deploy, duplicate email provider callbacks.
- [ ] Keep Docker-backed PostgreSQL/Redis jobs mandatory and add deployed CORS/gateway smoke plus external OAuth/passkey interoperability where feasible.
- [ ] Wire `SECURITY_ALERT` + security metrics to SIEM/PagerDuty; run one tabletop drill using DEPLOYMENT runbooks.
- [ ] Sign container images; enforce SBOM + dependency-check gates on release tags.
- [ ] Document backup/restore, Redis data-loss behavior, migration rollback policy, DR for keys and sessions.
- [ ] Privacy/ops proof: DSAR export drill, deletion + retention verification in staging, legal-basis doc pack.
- [ ] **Frontend security audit** (consumer app): XSS, token storage, redirects, CSRF header echo, route guards.
- [ ] Optional: worker mTLS in Kubernetes; external OIDC conformance log.

## Reference Authentication Model Assessment

AuthKit is substantially closer to a reference-grade architecture: token classes and trust boundaries are explicit; first-party access is session-bound; privileged operations use step-up; OAuth/OIDC, MFA, passkeys, key rotation, privacy-safe audit, durable email, distributed scheduling, abuse controls, and deployment contracts are all materially implemented and tested.

It is not reference-grade because implementation strength is ahead of operational evidence. A reference model needs repeatable load/soak results, dependency chaos, verified backup/restore, live alert routing and drills, frontend safety validation, external OIDC interoperability, signed/provenanced releases, and a production track record. The strict reference-model score is therefore **7.5/10**, not 9+.

## Risk Acceptance Notes

- Accepting production without Prompt 3 means accepting unknown p95/p99 and failure behavior under credential stuffing, Redis latency, DB pool pressure, scheduler contention, and provider outages.
- Leaving `AUTH_ABUSE_FAIL_CLOSED_HIGH_RISK=false` means replica count can multiply local degraded allowances during Redis outages unless ingress/WAF controls also enforce limits.
- Accepting unaudited frontend integration means XSS or unsafe token storage could defeat otherwise strong backend controls.
- Accepting unsigned images and no provenance/promotion gate increases supply-chain ambiguity during incident response, despite SBOMs and fixed-vulnerability Trivy gates.
- Accepting Docker-backed test skips locally means PostgreSQL/ShedLock/HSCAN behavior depends on CI execution; those jobs must remain mandatory and visible.

## Final Recommendation

Prompt 2.5 was effective. It closed the identified pre-proof security, durability, boundedness, observability-as-code, contract, and CI gaps without weakening existing APIs except for the approved session pagination contract.

**Current recommendation:** **approved only with compensating controls** for controlled small/medium production as a primary auth API. Required controls include managed PostgreSQL/Redis, TLS ingress, strict network policies, WAF/edge throttles, mandatory Docker migration/Redis tests in CI, alert routing, tested key/secret procedures, and a separately audited consuming frontend.

**After Prompt 3:** approved for **medium-scale horizontal production** (target **8.2–8.5** production readiness) as standalone service, embedded module, or monolith auth core — still not “reference-grade 9+” without frontend proof and operational track record.

**Strict final score:** **8.1/10 production readiness**, **8.2/10 security**, **7.4/10 performance/scalability**, **8.3/10 maintainability**, and **7.5/10 reference-model readiness**. Prompt 3 remains required for measured-scale confidence and broad production claims.
