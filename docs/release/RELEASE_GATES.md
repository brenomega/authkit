# AuthKit v0.1 release gates

[English](RELEASE_GATES.md) | [Português (Brasil)](RELEASE_GATES-ptBR.md)

English is authoritative when translations differ.

This document defines the mandatory gates for an AuthKit v0.1 release. It deliberately does not embed a mutable test count, commit, tree, image digest, or gate result: those values belong to the external evidence manifest produced after the source candidate is frozen. This avoids stale evidence and the impossible self-reference of storing a tree hash inside the tree it identifies.

Every result must identify one candidate by base commit, candidate tree, source-archive SHA-256, immutable OCI digest, and artifact manifest. `PASS` requires current objective evidence for that exact candidate. Missing, historical, partial, mocked-away, or contradictory evidence remains `NOT PROVEN`. No gate is optional for the golden path.

| # | Mandatory gate | Objective PASS condition | Evidence to preserve |
| --- | --- | --- | --- |
| 1 | Clean build and complete suite with real PostgreSQL and Redis | Java 21 clean build exits zero; all required tests run with zero failures, errors, or skips; PostgreSQL 17 and Redis 7 are real containers. | Full build log, Surefire/Failsafe XML, tool and container versions. |
| 2 | Fresh golden-path installation | An empty environment reaches healthy production state using only public instructions; documented positive smoke passes and unsafe/missing configuration fails fast. | Redacted Compose config, image IDs, Flyway state, health and smoke transcripts. |
| 3 | TLS/reverse proxy, same-site and cross-site | Both browser topologies pass TLS, cookie, CSRF, CORS and forwarded-header checks; public ingress and direct backend cannot satisfy the worker boundary. | Certificate chain, HAR/curl traces, proxy logs and firewall/network proof. |
| 4 | Real SMTP and Resend | Both providers accept registration/recovery messages; retry, crash/reclaim, deduplication and DEAD behavior satisfy the email contract. | Provider acceptance IDs, stable message IDs/idempotency keys, outbox rows and retry logs. |
| 5 | Real Google and independent generic OIDC | New/existing identity flows pass for both providers; restricted mode, state/nonce/issuer and collision negatives fail safely. | Redacted redirect traces, provider/audit IDs and account/link state. |
| 6 | External OAuth/OIDC interoperability and applicable conformance | An independent client and applicable conformance profile pass discovery, authorization code + PKCE, token, userinfo, introspection, revocation and negative cases without weakening suppressions. | Suite report, raw protocol traces and client configuration. |
| 7 | Downstream JWT/JWKS lifecycle | An independent verifier enforces exact issuer/audience/token class and demonstrates unknown `kid`, planned rotation, emergency revocation and account/session lifecycle invalidation. | JWKS snapshots/hashes, verifier logs and token metadata without raw tokens. |
| 8 | PostgreSQL/Redis backup and clean restore | Encrypted backups restore on an independent clean host with consistent application/security state and measured RPO/RTO; corrupt or partial input fails closed. | Backup hashes, encryption/checksum logs, restored counts and smoke results. |
| 9 | Controlled dependency failures | Redis, PostgreSQL and email failures preserve fail-closed/atomicity/outbox invariants, recover within the recorded time and route the required alerts. | Chaos logs, metrics, alert notifications and state snapshots. |
| 10 | Mixed load, hostile burst and soak | At least four hours on the 2 vCPU/4 GiB reference class meet published latency/error/resource thresholds; replay, abuse and oversized/chunked bodies are rejected without collapse. | k6 raw/summary data and host/JVM/PostgreSQL/Redis/outbox metrics. |
| 11 | Smoke, negative tokens, concurrency and one-time state | Required positive flows and negative corpus pass; every required race has exactly one winner or the documented fail-safe outcome in real stores. | Smoke logs, generated fixture manifest, race reports and final store state. |
| 12 | Zero unresolved runtime integrity indicators | The proof window ends with zero unresolved DEAD email, critical audit loss, integrity error, sustained pool wait or out-of-bound backlog. | Before/after Prometheus, SQL and Redis snapshots plus the exact time window. |
| 13 | Blocking security and supply-chain scans | Dependency, filesystem, container, static, secret and IaC scans complete with no unresolved blocking result or unjustified suppression. | Machine-readable reports, scanner versions/configuration and rationale for every suppression. |
| 14 | SBOM, checksums, signatures and provenance | Multi-architecture immutable artifacts, SBOMs, checksums, authorized signatures and verifiable provenance all bind to the same source and OCI digest. | OCI descriptors, SBOMs, checksum manifest, signatures, attestations and authorization record. |
| 15 | Fresh-operator clean-room proof | A context-isolated operator completes setup and required operations using only final public docs/artifacts, with no hidden step or ad-hoc normative edit. | Complete transcript, public inputs, candidate hashes and operator observations. |
| 16 | Zero unresolved P0/P1 in GA | Every P0/P1 is closed against the frozen candidate and its acceptance criteria are evidenced; no additional independent audit is required solely to close this gate. | Finding disposition matrix, evidence index and candidate identities. |

The generated evidence bundle and final consolidated audit are the only places that may state current gate results. They must use `PASS`, `FAIL`, or `NOT PROVEN` and must issue `GO` only when Gates 1–16 are all `PASS`. Promotion, publication and tagging remain maintainer-only actions.
