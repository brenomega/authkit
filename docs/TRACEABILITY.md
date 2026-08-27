# v0.1 requirement traceability

[Português (Brasil)](TRACEABILITY-ptBR.md) | English is normative.

This public matrix maps every independent-audit finding to the implemented contract and evidence. Detailed commands and file-level history remain in `docs/release/IMPLEMENTATION_MATRIX.md`; mandatory operational disposition remains in `docs/release/RELEASE_GATES.md`. `IMPLEMENTED` does not substitute for external proof or final audit.

| ID | Normative disposition | Main implementation/migration | Tests or proof | State |
| --- | --- | --- | --- | --- |
| AK-001 | Google and allowlisted generic OIDC RP; state/nonce/PKCE; `(issuer, subject)`; no email auto-link; explicit link/unlink; discard provider tokens | Social controllers/services/clients; V20 | Social-only, linking, issuer and one-time concurrency tests; real providers pending | IMPLEMENTED; EXTERNAL PROOF PENDING |
| AK-002 | Secure request/confirm/cancel email change with old-address notice and revocation | `EmailChangeService`; V17 | Positive, replay, collision and concurrent-winner tests | VERIFIED LOCAL |
| AK-003 | ACTIVE/SUSPENDED/DELETION_PENDING and irreversible anonymization; full suspend/reactivate | Lifecycle/admin services; V15–V16 | State, authority, audit and migration tests | VERIFIED LOCAL |
| AK-004 | Configurable 0–30-day deletion grace (default 7), cancel, idempotent anonymize/purge | Lifecycle/anonymization services; V15–V18 | Boundary, retry, cancellation and purge-permission tests | VERIFIED LOCAL |
| AK-005 | Only USER/PLATFORM_ADMIN; safe legacy migration; last-admin guard; personal `tenant_id`; global OAuth clients | Security/admin/tenant code; V15 | Fresh/upgrade roles and DB trigger tests; platform-admin filter regression | VERIFIED LOCAL |
| AK-006 | Nullable password for social-only accounts | User/auth services; V15 | Entity/login/social-only and PostgreSQL tests | VERIFIED LOCAL |
| AK-007 | Explicit public or restricted registration | Registration/config validator | Both modes and production fail-fast tests | VERIFIED LOCAL |
| AK-008 | Conventional GET authorize, exact redirects, standard errors, Code+PKCE S256/state/nonce | OAuth controller/service; V21 | Browser-transaction, redirect and PKCE tests | VERIFIED LOCAL; CONFORMANCE PENDING |
| AK-009 | Opaque rotating OAuth refresh families; replay revokes family | OAuth service/entities; V21 | Serial/concurrent rotation and replay-revocation tests | VERIFIED LOCAL |
| AK-010 | Standard userinfo/introspection/revocation; correct token classes/security chains; discovery/JWKS/ID token | OAuth/security code | Wire, audience, authentication, revocation and token-class tests | VERIFIED LOCAL; EXTERNAL CLIENT PENDING |
| AK-011 | Signed expiring resumable one-time login/consent transaction | OAuth transaction codec/service; V21 | Inspect/approve/deny/replay/audit rollback tests | VERIFIED LOCAL |
| AK-012 | One-shot non-HTTP admin bootstrap plus complete stepped-up platform admin plane | Bootstrap runner/service, admin plane; V25 | Serialized singleton, repeat rejection, audit rollback, cursor/session/admin tests and clean golden CLI drill | VERIFIED LOCAL |
| AK-013 | Safe session metadata, bounded lastSeen, authenticated first-party introspection and immediate revocation | Session metadata/storage/introspection; V19 | Redis 7/JDBC, paging, throttling and HTTP revocation tests | VERIFIED LOCAL |
| AK-014 | Atomic recovery and one-time storage with safe commit/retry/compensation | TokenStorage Redis Lua/JDBC and recovery services; V17 | Fault injection and real Redis/PostgreSQL claim lifecycle tests | VERIFIED LOCAL |
| AK-015 | Concurrent-safe confirmation and other one-time state | Registration/email-change locking | Barrier tests with exactly one winner | VERIFIED LOCAL |
| AK-016 | Required external operator templates, restricted renderer, safe fragment action URL, honest provider acceptance/retry | Email renderer/providers/outbox; V22 | Template traversal/variables, timing and local SMTP acceptance | VERIFIED LOCAL; REAL SMTP/RESEND PENDING |
| AK-017 | Critical audit synchronous and transactional; audit failure aborts mutation | Security event classification/service | Rollback fault-injection integration tests | VERIFIED LOCAL |
| AK-018 | Separate retention delete role/procedure and audited purge | Retention gateway; V18/V23 | PostgreSQL real-role permission and purge-log tests | VERIFIED LOCAL |
| AK-019 | Reject absent/ambiguous `token_use`; strict token classes | JWT decoder/use policy | Negative token fixture and decoder tests | VERIFIED LOCAL |
| AK-020 | No test profiles/private keys in production artifacts/context | Maven/Docker/.dockerignore/inspection harness | JAR, exact context and final local image inspection | VERIFIED LOCAL |
| AK-021 | Monotonic concurrency-safe passkey counter; step-up and last-authenticator invariant | Passkey/social/MFA services; V16/V20 | CAS/replay/concurrency and authenticator-removal tests | VERIFIED LOCAL; REAL CEREMONY PENDING |
| AK-022 | Complete versioned export without secrets | Profile/export services | Full fixture/redaction and step-up/audit coverage | VERIFIED LOCAL |
| AK-023 | Canonical prod profile and hardened AuthKit+PG17+Redis7+TLS Compose with mounted secrets | `application-prod.yml`, `deploy/golden`, V23 | Fresh V1→V25 install, TLS health, bootstrap and manual flow | VERIFIED LOCAL; INDEPENDENT OPERATOR PENDING |
| AK-024 | Retry-After, duplicate rejection, strict JSON, HTTPS CORS, trusted proxy peers, high-risk Redis fail-closed | Edge filters/config | Negative HTTP, proxy spoof/depth and failure tests | VERIFIED LOCAL |
| AK-025 | Semantic OpenAPI, schemas/validation/headers/examples/errors/pagination, AuthKit requestId vs standard OAuth wire | OpenAPI, response/error handling | Semantic contract and manual correlation tests | VERIFIED LOCAL |
| AK-026 | Complete negative/concurrency/one-time matrix | Cross-cutting test suites | Final clean suite: 289/289 plus real PG17/Redis7 and manual negatives | VERIFIED LOCAL |
| AK-027 | Real TLS/providers/client/JWKS proofs | Reproducible instructions/harness boundary | Local TLS/sample passed; real providers, public topologies, conformance and rotation absent | PARTIAL LOCAL; EXTERNAL PROOF PENDING |
| AK-028 | Backup/restore, controlled failure, alert/runbook, mixed/burst/4h soak | Operations docs and proof harnesses | Clean-container restores and local dependency drills passed; off-host/clean-host, alerts and 4h soak absent | PARTIAL LOCAL; EXTERNAL PROOF PENDING |
| AK-029 | Blocking scans, amd64/arm64 OCI digest, SBOM, checksums, signature, provenance | CI and local evidence automation | Local tools/maintainer signing identity absent | PARTIAL; NOT PROVEN |
| AK-030 | Complete normative EN and integral pt-BR docs; same-site and cross-site examples | Canonical docs and `samples/` | Resource-server tests, JS syntax and link/pair scan pass | VERIFIED LOCAL |
| AK-031 | Apache-2.0 and mandatory OSS policies; DCO/no CLA; POM metadata | Root policy/license files and POM | Maven model/build validation | VERIFIED LOCAL |
| AK-032 | No overstated claims or obsolete prompt/audit prose in public corpus | Canonical docs and absorbed historical cleanup | Claim/reference scan passes; V11/V12 comments retained for Flyway checksum compatibility | VERIFIED LOCAL |
| AK-033 | Honest experimental/unsupported opt-in support matrix | Bilingual support matrix and config isolation | Defaults/regression tests | IMPLEMENTED |
| AK-034 | Golden prod Redis/direct/SMTP TLS/HIBP/fail-closed/TTL≤300 defaults; Resend alternative | Prod/golden config | Validator/provider tests; Compose validation | VERIFIED LOCAL |
| AK-035 | Remove phone from model, DB, DTO/export/OpenAPI/docs | User model/contracts; V15 | Compile/search and migrated-data tests | VERIFIED LOCAL |
| AK-036 | Coherent unpublished candidate and evidence bound to tree/digest | `0.1.0-rc.1`, changelog/release automation | Local evidence binds baseline HEAD, tree manifests and immutable image ID; registry proof pending | VERIFIED LOCAL; EXTERNAL PROOF PENDING |
| AK-037 | `ACCEPTED` means provider acceptance, never inbox delivery | Outbox/provider model; V22 | Migration/provider/local SMTP row tests | VERIFIED LOCAL; REAL PROVIDERS PENDING |

The release remains `NO-GO` while any mandatory gate is `NOT PROVEN` or pending and until a new independent audit reports no unresolved GA P0/P1.
