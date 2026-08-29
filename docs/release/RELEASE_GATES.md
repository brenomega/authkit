# AuthKit v0.1 release gates

[Português (Brasil)](RELEASE_GATES-ptBR.md) | English is normative.

This is the final internal validation ledger for the unpublished `0.1.0-rc.1` remediation candidate on branch `release/authkit-v0.1.0-rc1-final-audit`, based on commit `23a6ad66bec32ce247ce8505dd4035a4f9865014` (tree `7a895d2fe552e032f4bfc05293b939f94480cbfa`) plus the explicitly uncommitted remediation patch. `PASSOU` records completed evidence for the gate as scoped below. `NÃO COMPROVADO` is never inferred from code, mocks or historical evidence. No gate is `NÃO APLICÁVEL` to the golden path.

| # | Mandatory gate | State | Current evidence | Exact remaining action |
| --- | --- | --- | --- | --- |
| 1 | Clean build and complete suite with real PostgreSQL/Redis | PASSOU | Exact `./mvnw clean verify -B`: 303 tests, 0 failures, 0 errors, 0 skips; PostgreSQL 17.9 and Redis 7.4 ran through digest-pinned Testcontainers; JAR and CycloneDX SBOMs were generated. | Rerun only if a code, test or build input changes before freeze. |
| 2 | Fresh golden-path install using production configuration | PASSOU | From-empty isolated volumes reached Flyway V25 with PostgreSQL 17.9, Redis 7.4, AuthKit, Caddy and Mailpit healthy. TLS hostname validation, discovery/JWKS, registration, SMTP STARTTLS acceptance, confirmation/replay, login, refresh, profile, invalid credentials, one-shot bootstrap/replay and Redis fail-closed recovery passed. | Preserve the local proof; public TLS/provider proofs remain in their own gates. |
| 3 | TLS/proxy in same-site and cross-site browser topologies | NÃO COMPROVADO | Local Caddy TLS and edge tests passed, but no real DNS/browser run covered both declared topologies. | Execute both topologies with public DNS/certificates and preserve browser/curl origin, cookie, CORS and direct-backend-denial traces. |
| 4 | Real SMTP and Resend | NÃO COMPROVADO | Mailpit proves local SMTP STARTTLS provider acceptance only. | Run real SMTP and Resend accounts, preserve provider acceptance IDs, and record inbox/spam observation separately. |
| 5 | Real Google and independent generic OIDC | NÃO COMPROVADO | Local OIDC protocol/negative/linking/consent tests pass after AUD-003/AUD-004. | Execute Google and independent generic OIDC with real client registrations and exact redirects. |
| 6 | External OAuth/OIDC client and applicable conformance | NÃO COMPROVADO | Local authorization-code, PKCE, wire and OpenAPI tests pass. | Run an independent client and the applicable conformance suite against the public TLS deployment. |
| 7 | Downstream JWKS unknown-`kid`, rotation, revocation and lifecycle invalidation | NÃO COMPROVADO | Resource-server sample passed 2/2; local missing/unknown/duplicate/revoked `kid` tests and OAuth lifecycle tests pass. | Exercise an independent downstream validator through planned/emergency rotation, cache refresh, revocation and account lifecycle changes. |
| 8 | PostgreSQL/Redis backup and clean-host restore | NÃO COMPROVADO | Local clean-container restores passed: PostgreSQL at Flyway 25 with representative user/consent/outbox data, and Redis with 20 keys. | Encrypt and transfer backups off-host; restore on an independent clean host and record RPO/RTO plus functional reconciliation. |
| 9 | Controlled PostgreSQL, Redis and email failures with alert routing | NÃO COMPROVADO | Real Redis outage returned opaque 503 and recovered; revocation service outage/restart tests pass. PostgreSQL/email alert delivery was not rerun for this candidate. | Execute all three failures in the reference environment and prove alert delivery, escalation and recovery timing. |
| 10 | Mixed load, hostile burst and at least four-hour soak | NÃO COMPROVADO | Harness and concurrency tests exist; no current four-hour reference-host run was executed. | Run at least four hours on 2 vCPU/4 GiB and retain latency, throughput, error, CPU, memory, GC, pool, Redis, Argon2 and outbox metrics. |
| 11 | Smoke, negative tokens, concurrency and one-time state | PASSOU | Clean suite includes real PostgreSQL/Redis lifecycle, refresh/suspension race, social state, consent rollback, migration, durable revocation and outage tests. Golden HTTP rejected confirmation replay, wrong password and unavailable Redis. | Rerun only if the candidate changes. |
| 12 | Zero DEAD outbox, audit loss, integrity error or pool wait under proof load | NÃO COMPROVADO | Functional golden flow recorded one `ACCEPTED` message and consistent consent/user rows; no Gate 10 load observation exists. | Query and preserve all required zero/non-zero counters after Gates 9–10. |
| 13 | Dependency, container, static, secret, IaC and supply-chain scans | NÃO COMPROVADO | Tracked secret-pattern search and artifact inspection found no release secret; `trivy`, `gitleaks`, `semgrep`, `checkov` and `hadolint` were unavailable locally. | Run the blocking scanner set against the frozen source and immutable image; archive machine-readable reports and justified suppressions. |
| 14 | SBOM, checksums, signature and verifiable provenance | NÃO COMPROVADO | CycloneDX JSON/XML, immutable build-input inventory, checksums and unsigned local provenance are generated; no immutable published digest or maintainer signature exists. | Freeze the source, build the publication artifact, sign its digest and attach registry-verifiable provenance under explicit publication authorization. |
| 15 | Setup by a fresh operator using only public documentation | NÃO COMPROVADO | The final local run followed the canonical configuration and corrected SMTP/SAN procedure, but it was not performed by an independent fresh operator. | Give only public release inputs to a fresh operator/environment and preserve the result. |
| 16 | Zero known P0/P1 in GA after final implementation validation | PASSOU | Internal final review rechecked AUD-001–AUD-010, full code/test diff, semantic OpenAPI, real PostgreSQL/Redis, golden API, artifacts and documentation. All five P1 and all required P2/P3 remediations are disposed; the final clean suite has no failure or skip and no new known GA P0/P1 was found. | Reopen only if the candidate changes or a new concrete P0/P1 is reported. |

## Final local evidence identities

| Item | Identity |
| --- | --- |
| Application JAR | `sha256:9869de06d5a0724993f0d27f93009e704065ee6df4b190a237c60b44e3de1882` |
| CycloneDX JSON | `sha256:3f37f87d00e53bc38400b4aaea139059136aa990b87aeb8fcaf759b9133e3a58` |
| CycloneDX XML | `sha256:6a13a3f9883d591868cfadad835419f5036c5a1768ba1c32d6478dd75ea47d3d` |
| Local image | `sha256:97e7c8d6e999e5fedafaad87b75474e0fd4bd9fa518ba9aa6406b7f090877e3c` |
| Full local manifest/checksums | `target/release-evidence/manifest.json` and `target/release-evidence/checksums.sha256` (ignored, unpublished) |

The implementation is internally validated and Gate 16 is closed. Release remains blocked by every `NÃO COMPROVADO` mandatory external gate and by the absence of a frozen committed tree, immutable publication digest, signature and human publication authorization. No tag, push, publication or promotion was performed.
