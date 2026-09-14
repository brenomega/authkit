# AuthKit v0.1 use-case catalog

[English](USE_CASES.md) | [Português (Brasil)](USE_CASES-ptBR.md)

English is authoritative when translations differ. Every case uses the normative template: objective, actors, trigger, preconditions, main flow, failure flows, postconditions, security properties, components, endpoints, state, and tests. OpenAPI remains the exhaustive operation-level contract; this catalog groups related operations into end-to-end user outcomes.

## UC-003 — Register a local account

- Objective: create one tenant-owned local identity without account enumeration.
- Actors/trigger: anonymous browser submits registration.
- Preconditions: `registration.mode=public`, accepted current policy versions, password policy and abuse controls available.
- Main flow: normalize email; arbitrate uniqueness; hash password; snapshot consent; create hashed confirmation state and durable outbox message; return the configured public outcome.
- Failure flows: restricted mode denies; duplicate follows stealth policy; audit/outbox failure rolls back; concurrent losers never return 500.
- Postconditions/security: one User, one current confirmation, one consent event; no raw token in SQL/logs.
- Components/endpoints/state/tests: `RegistrationService`; `/api/v1/auth/register`, confirmation/resend; `users`, `consent_events`, `email_outbox`; OpenAPI Register operations; registration concurrency and confirmation one-winner proofs.

## UC-016 — Change the primary email securely

- Objective: transfer the primary identifier only after local step-up and proof of the new mailbox.
- Actors/trigger: authenticated user requests, confirms, replaces, or cancels an email-change ceremony.
- Preconditions: active confirmed account, current consent, password and MFA when enrolled.
- Main flow: serialize on User, store only token hash and expiry, enqueue notification, lock and consume on confirm, update normalized unique email, revoke first-party and OAuth renewable lineages after commit.
- Failure flows: duplicate email, expired/wrong token, cancel-vs-confirm and request-vs-confirm races have one terminal outcome; critical audit failure rolls back.
- Postconditions/security: old refresh families fail; prior/new recovery tokens are revoked; old address receives notification.
- Components/endpoints/state/tests: `EmailChangeService`, `OAuthLifecycleRevocationService`; `/api/v1/users/me/email-change`, `/api/v1/auth/email-change/confirm`; `users`, OAuth refresh tables, outbox/audit; email ceremony concurrency and lifecycle tests.

## UC-019 — Request account deletion

- Objective: enter the configured privacy grace period or anonymize immediately.
- Actors/trigger: authenticated user completes local step-up and deletion request.
- Preconditions: active confirmed account, current consent, distributed high-risk abuse control, not the last active platform administrator.
- Main flow: lock the global admin invariant then User, persist deletion timestamp/state and critical audit, revoke OAuth state in SQL, revoke external sessions after commit.
- Failure flows: audit/SQL failure rolls back; last-admin attempt denies; concurrent admin removals serialize.
- Postconditions/security: deletion pending or anonymized; writes/authentication denied; identity never silently restored.
- Components/endpoints/state/tests: `AccountLifecycleService`; `DELETE /api/v1/users/me`; `users`, social/OAuth/outbox/audit; last-admin PostgreSQL matrix and lifecycle tests.

## UC-020 — Cancel deletion before cutoff

- Objective: restore a pending account only while the grace interval is open.
- Actors/trigger: platform administrator with local step-up requests cancellation.
- Preconditions: target locked in `DELETION_PENDING`; current time strictly before requested-at plus grace.
- Main/failure flow: validate deadline under the same row lock as anonymization; cancel and audit before cutoff; deny at/after cutoff or after anonymization.
- Postconditions/security: exactly one of cancel/anonymize wins and an expired deletion never ends ACTIVE.
- Components/endpoints/state/tests: `AdminService`, `AccountAnonymizationService`; `DELETE /api/v1/admin/users/{userId}/deletion`; `users`, security events; cutoff boundary and race proof.

## UC-028 — Detect stale consent

- Objective: expose accepted and required policy versions and a stable `consentRequired` decision.
- Actors/trigger: authenticated user reads consent after operator raises a version.
- Preconditions: valid live first-party session.
- Flow/properties: compare both exact versions server-side; allow consent read while the account is limited; never infer currency from booleans alone.
- Components/endpoints/state/tests: `AccountLifecycleService`, `UserAuthoritiesFilter`; `GET /api/v1/users/me/consent`; `users`, consent ledger; full-context consent proof.

## UC-029 — Enforce consent-limited credentials

- Objective: prevent a stale-consent session from normal writes, refresh and OAuth authorization.
- Actors/trigger: stale account calls a protected operation.
- Flow/failures: permit only consent read/accept and logout; return stable `consent_required`; dependency loss fails unavailable; OAuth uses its protocol error surface.
- Postconditions/security: no new renewable lineage or authorization code is issued before acceptance.
- Components/endpoints/state/tests: `UserAuthoritiesFilter`, `AuthService`, `OAuthProviderService`; protected APIs, refresh and authorize; HTTP/filter/service integration tests.

## UC-030 — Accept current consent

- Objective: atomically accept the exact versions presented by the server.
- Actors/trigger: limited authenticated user posts both true acknowledgements and exact versions.
- Preconditions: active confirmed account and versions equal current configuration.
- Main/failure flow: lock User; update timestamp/version/lawful basis; append consent and critical audit evidence; commit then evict authority cache. Stale versions return conflict; audit failure rolls back; concurrent calls are idempotent.
- Postconditions/security: normal authorization resumes only after durable commit.
- Components/endpoints/state/tests: `POST /api/v1/users/me/consent`; `users`, `consent_events`, `security_events`; rollback and concurrency proof.

## UC-067 — Authenticate or create a social identity

- Objective: authenticate immutable `(issuer, subject)` identities without email auto-link.
- Actors/trigger: anonymous browser completes Google or generic OIDC authorization-code/PKCE callback.
- Preconditions: allowlisted enabled provider, one-time state/nonce/verifier, verified issuer/signature/audience/email.
- Main flow: existing link authenticates in all registration modes; a new subject creates User/consent/link only in public mode.
- Failure flows: restricted new identity, email collision, state replay, provider error or consent persistence failure create no partial identity.
- Components/endpoints/state/tests: `SocialIdentityService`, `SocialOidcClient`; social start/callback; social provider/transaction/identity/User/consent tables; PostgreSQL social integration and external-provider proof.

## UC-109 — Preserve the last platform administrator

- Objective: guarantee at least one active platform administrator under all removal races.
- Actors/trigger: administrators demote, suspend or delete distinct administrators concurrently.
- Preconditions: local password step-up plus TOTP or fresh passkey.
- Main/failure flow: every removal locks the same ordered set of active-admin rows, then locks target and re-counts; at most one transaction wins.
- Postconditions/security: `active_admin_count >= 1` after demote/demote, suspend/suspend, delete/delete and all mixed pairs.
- Components/endpoints/state/tests: `AdminService`, `AccountLifecycleService`, `UserRepository`; admin role/suspension and user deletion operations; PostgreSQL 17 barrier matrix.

## UC-137 — Authorize an internal worker

- Objective: require two independent factors: trusted internal network and rotatable worker token.
- Actors/trigger: retention/introspection worker or Prometheus reaches an internal path.
- Main/failure flow: public TLS proxy returns 404 regardless of token; direct internal request fails with network-only or token-only and passes with both; previous token usage is metered during bounded rotation.
- Components/endpoints/state/tests: Caddy, `WorkerAuthFilter`; `/api/v1/internal/**`, `/actuator/prometheus`; proxy topology proof.

## UC-138 — Fail high-risk abuse controls closed

- Objective: prevent distributed-limit bypass when Redis is absent.
- Actors/trigger: any high-risk policy is evaluated during startup/runtime Redis loss.
- Main/failure flow: every `highRisk` enum member returns dependency-unavailable and increments policy-tagged fail-closed metrics; only explicitly non-high-risk operations may use local fallback.
- Components/endpoints/state/tests: `AbuseThrottleService`, `AbuseRateLimitPolicy`; authentication, recovery, OAuth, admin and lifecycle endpoints; exhaustive policy test and controlled Redis outage.

## Traceability matrix

| Use case | Endpoint / contract | Service | Persistence | Security control | Proof |
|---|---|---|---|---|---|
| UC-003 | Register/confirmation OpenAPI operations | RegistrationService | users, consent_events, email_outbox | uniqueness, Argon2, hashed token, stealth | registration and confirmation concurrency |
| UC-016 | email-change operations | EmailChangeService | users, OAuth refresh, outbox/audit | row lock, local step-up, post-commit revocation | email race + old-family rejection |
| UC-019/020 | deletion/admin deletion | AccountLifecycleService/AdminService | users, social/OAuth/audit | aggregate+row locks, strict cutoff | PostgreSQL mixed race + boundary time |
| UC-028/029/030 | consent GET/POST, refresh, authorize | AccountLifecycle/Auth/OAuth | users, consent/audit | exact versions, limited credential, critical audit | full-context, rollback, concurrent accept |
| UC-067 | social start/callback | SocialIdentityService | social tables, users, consent | OIDC verification, immutable subject, registration policy | PostgreSQL + Google/generic external |
| UC-109 | admin role/suspension, deletion | Admin/AccountLifecycle | users, security_events | global lock, step-up, second factor | PostgreSQL 17 six-pair barrier matrix |
| UC-137 | internal/Prometheus | WorkerAuthFilter + Caddy | metrics/audit | independent network+token | public/internal topology matrix |
| UC-138 | high-risk endpoints | AbuseThrottleService | Redis + metrics | fail closed | exhaustive enum + Redis stop/recovery |
