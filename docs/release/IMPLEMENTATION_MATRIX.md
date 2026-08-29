# AuthKit v0.1.0 implementation matrix

English is normative. This ledger describes the uncommitted remediation candidate requested after the independent pre-release audit. It is implementation evidence, not release approval.

## Candidate identity and evidence semantics

| Field | Current value |
| --- | --- |
| Branch | `release/authkit-v0.1.0-rc1-final-audit` |
| Base commit | `23a6ad66bec32ce247ce8505dd4035a4f9865014` |
| Base commit tree | `7a895d2fe552e032f4bfc05293b939f94480cbfa` |
| Candidate state | Tracked and release-relevant untracked remediation is intentionally uncommitted; the working tree is not frozen |
| Flyway | V1–V25 unchanged by this remediation |
| Publication authorization | None; no commit, tag, push, signature, publication or promotion was performed |
| Evidence binding | `target/release-evidence/manifest.json` binds the base commit, tracked patch hash, release-relevant untracked manifest and local image ID |

The terms below are deliberately distinct:

- `IMPLEMENTED`: code/configuration exists in the current working candidate.
- `VERIFIED LOCAL`: an automated local test passed.
- `PROVED REAL`: the path ran against a real local dependency or container, not a mock.
- `EXTERNAL PROOF PENDING`: credentials, infrastructure, independent operator or publication authority was unavailable.
- `HUMAN AUTHORIZATION PENDING`: only a maintainer may freeze, sign or publish the candidate.

## Independent-audit remediation dispositions

| Audit ID | Disposition | Implementation | Objective acceptance evidence |
| --- | --- | --- | --- |
| AUD-001 | RESOLVED | Corrected PostgreSQL purge SQL construction; Docker-dependent tests fail instead of silently skipping; PostgreSQL/Redis images are digest-pinned. | Exact `./mvnw clean verify -B`: 303 tests, 0 failures, 0 errors, 0 skips; PostgreSQL 17.9 and Redis 7.4 ran for real. |
| AUD-002 | RESOLVED | Suspension, deletion request and anonymization synchronously revoke OAuth refresh families. Access tokens carry a durable account lifecycle epoch; introspection/userinfo verify account state and epoch. Lock ordering serializes issuance/refresh with lifecycle transitions. | Real PostgreSQL tests cover access and refresh invalidation, reactivation non-resurrection, deletion, and concurrent refresh versus suspension. |
| AUD-003 | RESOLVED LOCALLY | Social RP accepts only the configured singleton audience and, when present, requires `azp` to equal the configured client; nonce and subject remain mandatory. | Negative fixtures reject extra audience, missing/wrong `azp`, wrong client, wrong nonce and blank subject. Real Google/generic-provider proof remains external. |
| AUD-004 | RESOLVED | Social signup applies configured terms/privacy/lawful-basis and appends exactly one immutable consent event in the same transaction as user/identity creation. | Real PostgreSQL test proves configured export/history, rollback on ledger failure and one-winner concurrent state consumption. |
| AUD-005 | RESOLVED LOCALLY | Every GA success response with a body has a concrete OpenAPI schema; OAuth no-body revocation is explicit; OAuth errors/introspection 503 are modeled. | Semantic parser and reflection-backed controller/DTO contract test pass; representative golden responses were exercised. External generated-client/conformance proof remains pending. |
| AUD-006 | RESOLVED IN CANDIDATE | `.agents/` and `skills-lock.json` are deleted from the release candidate; obsolete role Javadocs are corrected; the private audit report is excluded from Docker/evidence/docs-distribution checks. | Distribution/context inspection passes; no migration changed; `git diff --check` passes. Deletions become part of Git history only after an authorized future commit. |
| AUD-007 | RESOLVED | Startup rejects missing/invalid/duplicate/revoked active or retiring key IDs. Both first-party and OAuth decoders require a nonblank currently published `kid`. | Negative key/config tests cover missing, unknown, duplicate and active-revoked IDs; JWKS golden response publishes the active ID. External downstream rotation drill remains pending. |
| AUD-008 | RESOLVED | Redis/JDBC is authoritative for revoked OAuth JTIs; the local cache accelerates positive results only. Read/write degradation meters failure and throws a 503 `temporarily_unavailable` response instead of accepting unknown state. | Unit tests, real Redis restart/reconstruction and real Redis outage tests pass. Golden Redis outage returned opaque 503 and recovered. |
| AUD-009 | RESOLVED LOCALLY | Maven distribution/wrapper checksums, Docker bases, Compose services, restore/load/truststore helpers and Testcontainers/Ryuk are fixed by immutable digest/SHA. Evidence records all resolved image inputs and SBOM identity. | Two isolated clean Maven builds produce identical JAR and CycloneDX hashes; Docker context/JAR/image inspection passes. Registry signature and published provenance remain external. |
| AUD-010 | RESOLVED AND REPRODUCED | Local SMTP instructions now require SANs for both the proof public host and `DNS:mailpit`, use the exact `.pem` filenames, build a combined JVM truststore and include start/acceptance commands. | From-empty local secrets produced hostname-valid STARTTLS and one Mailpit message; `email_outbox` recorded one `ACCEPTED` row. This is not real-provider/inbox proof. |

## AK-001–AK-037 current disposition

| AK | Current disposition | Evidence boundary |
| --- | --- | --- |
| AK-001 | VERIFIED LOCAL / EXTERNAL PROOF PENDING | OIDC RP validation/linking tests pass after AUD-003; Google and independent generic OIDC remain external. |
| AK-002 | VERIFIED LOCAL | Email-change request/confirm/cancel, collision, replay and revocation coverage remains green. |
| AK-003 | PROVED REAL LOCALLY | PostgreSQL lifecycle tests now include OAuth access/refresh invalidation and non-resurrection. |
| AK-004 | PROVED REAL LOCALLY | Deletion/anonymization lifecycle and OAuth invalidation pass; retention operations remain separately governed. |
| AK-005 | VERIFIED LOCAL | Only `USER`/`PLATFORM_ADMIN`; personal opaque partition and last-admin protections remain green. |
| AK-006 | VERIFIED LOCAL | Social-only nullable-password account path passes with real PostgreSQL. |
| AK-007 | VERIFIED LOCAL | Public/restricted registration and production fail-fast remain covered; golden used intentional public mode. |
| AK-008 | VERIFIED LOCAL / EXTERNAL PROOF PENDING | Authorization Code + PKCE/resumable transaction pass; independent standards client remains external. |
| AK-009 | PROVED REAL LOCALLY | Opaque refresh rotation/replay/concurrency and lifecycle revocation pass on PostgreSQL. |
| AK-010 | PROVED REAL LOCALLY / EXTERNAL PROOF PENDING | Live introspection/userinfo/revocation now fail closed; interoperability remains external. |
| AK-011 | VERIFIED LOCAL | Signed expiring one-time authorization transaction and consent resume tests pass. |
| AK-012 | PROVED REAL LOCALLY | Offline bootstrap succeeded once on golden PostgreSQL and repeat execution was rejected. |
| AK-013 | VERIFIED LOCAL | First-party session metadata/introspection/logout behavior remains covered. |
| AK-014 | PROVED REAL LOCALLY | Redis/JDBC recovery claim/finalize/compensation coverage remains green. |
| AK-015 | PROVED REAL LOCALLY | Confirmation, social state and email-change concurrency have exactly one winner. |
| AK-016 | PROVED REAL LOCALLY / EXTERNAL PROOF PENDING | Template/outbox/SMTP STARTTLS acceptance passed locally; real SMTP and Resend remain external. |
| AK-017 | VERIFIED LOCAL | Critical audit failure rolls back protected mutations, including social consent. |
| AK-018 | PROVED REAL LOCALLY | PostgreSQL runtime/retention role and purge relationships pass. |
| AK-019 | VERIFIED LOCAL | Strict token class plus mandatory published `kid` tests pass. |
| AK-020 | PROVED REAL LOCALLY | JAR, Docker context and runtime image contain no test profile/private key material. |
| AK-021 | VERIFIED LOCAL / EXTERNAL PROOF PENDING | Passkey invariants pass; real authenticator ceremony remains external. |
| AK-022 | PROVED REAL LOCALLY | Social configured consent and immutable history appear in full export without secrets. |
| AK-023 | PROVED REAL LOCALLY / INDEPENDENT OPERATOR PENDING | Fresh golden stack reached healthy V25 and completed selected golden flows. |
| AK-024 | VERIFIED LOCAL | Strict request parsing, proxy/CORS and Redis high-risk fail-closed behavior remain green. |
| AK-025 | VERIFIED LOCAL / EXTERNAL CLIENT PENDING | Canonical OpenAPI is semantically typed and reflection-checked. |
| AK-026 | PROVED REAL LOCALLY | Clean suite is 303/303 with real PostgreSQL/Redis and no skips. |
| AK-027 | EXTERNAL PROOF PENDING | Public TLS/browser topology/providers/conformance/downstream rotation were not executed. |
| AK-028 | PARTIAL LOCAL / EXTERNAL PROOF PENDING | Clean-container PostgreSQL/Redis restore and Redis fault injection passed; off-host/clean-host/alerts/soak remain external. |
| AK-029 | PARTIAL LOCAL / EXTERNAL PROOF PENDING | Immutable inputs, SBOM and local provenance exist; blocking scanners/signature/registry attestation are not proved. |
| AK-030 | VERIFIED LOCAL | Documentation/link checker, shell syntax, JavaScript syntax and resource-server sample pass. |
| AK-031 | VERIFIED LOCAL | Apache-2.0 and OSS policy/governance metadata are unchanged and present. |
| AK-032 | VERIFIED IN CANDIDATE | Agent material removed, stale Javadocs corrected and evidence claims regenerated. |
| AK-033 | IMPLEMENTED / PROMOTION PROOF PENDING | Preview/unsupported paths remain explicit and opt-in. |
| AK-034 | PROVED REAL LOCALLY / EXTERNAL PROVIDERS PENDING | Golden Redis/direct SMTP/HIBP/300-second token defaults ran locally. |
| AK-035 | VERIFIED LOCAL | Phone remains absent from code/schema/contracts. |
| AK-036 | IMPLEMENTED / FREEZE PENDING | Current evidence binds the uncommitted patch; immutable committed tree/signature/publication do not yet exist. |
| AK-037 | PROVED REAL LOCALLY / EXTERNAL INBOX PENDING | SMTP provider acceptance maps to `ACCEPTED`; no inbox-delivery claim is made. |

## Current real commands and results

| Command/proof | Result |
| --- | --- |
| `./mvnw clean verify -B` | BUILD SUCCESS; 303 tests; 0 failures/errors/skips; 2m40s in the first full remediation run. Final evidence reruns the same command after ledger regeneration. |
| `../../mvnw test -B` in `samples/resource-server-spring` | BUILD SUCCESS; 2 tests; 0 failures/errors/skips. |
| `PostgresMigrationTest` | PostgreSQL 17.9; 5/5; fresh V1–V25, representative V14–V25 upgrade, rerun, retention and purge relationships. |
| `RedisTokenStorageContainerTest` | Redis 7.4; 6/6; durable reconstruction and outage behavior included. |
| `OAuthProviderServiceTest` | PostgreSQL 17.9; 13/13; lifecycle and concurrency included. |
| `SocialIdentityServiceIntegrationTest` | PostgreSQL 17.9; 6/6; consent/export/rollback/concurrency included. |
| OIDC/key/revocation/OpenAPI negative set | 11/11; 0 failures/errors/skips. |
| OpenAPI semantic/controller/DTO contract | 65 controller operations represented; all GA success bodies concretely typed; explicit no-body revocation. |
| Golden Compose/API | Healthy PostgreSQL 17.9, Redis 7.4, AuthKit, Caddy and Mailpit; TLS discovery/JWKS, registration, SMTP acceptance, confirmation/replay, login, refresh, profile and negative credentials passed. |
| Golden fault injection | Redis stopped: correct login returned opaque 503 with request ID; Redis restart restored health. |
| Backup/restore | PostgreSQL restored at Flyway 25 with user/consent/accepted-outbox data; Redis restored 20 keys in a clean read-only container. |
| Artifact inspection | JAR/context/image passed; image runs as `appuser`; no test profile, test key or private-key marker. |
| Documentation/scripts/Compose | 46 distributed Markdown files, 12 bilingual pairs, 37 AK rows; shell and JavaScript syntax pass; all Compose files resolve using declared examples. |
| Scanner inventory | `trivy`, `gitleaks`, `semgrep`, `checkov`, and `hadolint` unavailable; Gate 13 remains NOT PROVEN. |
| `git diff --check` | PASS. |

## Artifact identities from the reproducibility run

| Artifact | SHA-256 / identity |
| --- | --- |
| Application JAR | `9869de06d5a0724993f0d27f93009e704065ee6df4b190a237c60b44e3de1882` |
| CycloneDX JSON | `3f37f87d00e53bc38400b4aaea139059136aa990b87aeb8fcaf759b9133e3a58` |
| CycloneDX XML | `6a13a3f9883d591868cfadad835419f5036c5a1768ba1c32d6478dd75ea47d3d` |
| Local single-platform image | `sha256:97e7c8d6e999e5fedafaad87b75474e0fd4bd9fa518ba9aa6406b7f090877e3c` |
| Evidence checksums | `target/release-evidence/checksums.sha256` (local, ignored, unpublished) |

## Sanitization allowlist

The final remediation diff is limited to:

1. OAuth lifecycle epoch/revocation and lock-order implementation plus tests.
2. OIDC audience/`azp`, social consent atomicity, key-ID validation and fail-closed revocation plus negative tests.
3. Semantic OpenAPI schemas and stronger controller/DTO contract tests.
4. Immutable Maven/container/Testcontainers/restore/load/truststore inputs and evidence metadata.
5. Deletion of `.agents/` and `skills-lock.json`, correction of stale Javadocs and local SMTP proof documentation.
6. Evidence ledgers regenerated from this remediation run.

No V1–V25 migration was edited. The independent report `pre-release-audit.md` remains untracked and unchanged; it is audit input, not a distributable product file.

## Release boundary

The implementation is locally remediated and internally validated; Gate 16 is closed. External gates, an immutable committed tree/image, maintainer signing and publication authorization remain mandatory before release.
