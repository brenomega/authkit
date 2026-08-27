# Operations and incident response

[Português (Brasil)](OPERATIONS-ptBR.md) | English is normative.

The operator owns host hardening, DNS/TLS, secrets, legal text, email content and deliverability, provider accounts, backups/off-host encryption, alert routing, capacity validation, upgrades, and incident decisions. AuthKit supplies health/metrics, audit primitives, bounded jobs, revocation APIs, and reproducible harnesses; it is not an external SIEM, mailbox, backup service, or compliance certification.

## Routine checks

- Probe `/actuator/health` through TLS and scrape `/actuator/prometheus` only from a trusted network with `X-Worker-Token`.
- Watch request errors/latency, Argon2 saturation, PostgreSQL pool, Redis failures, authentication failures, lockouts, refresh replay, audit persistence failures, outbox backlog/age/dead count, and retention outcomes.
- Use `GET /api/v1/admin/operations` for non-secret outbox acceptance counts and configured posture. Use the cursor-bounded security-event endpoint for investigations; export to an operator SIEM when required.
- Treat `ACCEPTED` as provider acceptance. Track inbox observation separately and never alert on acceptance as if it proved delivery.

## Failure policy

| Failure | Expected behavior | Operator action |
| --- | --- | --- |
| Redis unavailable | High-risk golden-path auth operations fail closed; existing offline JWT consumers remain bounded by access expiry. | Restore Redis, inspect saturation/network/auth, verify replay/session state, then test login/refresh/logout. |
| PostgreSQL unavailable | Mutations and live-state checks fail; opaque 5xx responses avoid detail leakage. | Stop risky traffic, restore primary/connection pool, verify Flyway state and audit continuity. |
| Audit write unavailable | Critical boundary mutations abort and return unavailable. | Restore audit persistence before retrying; confirm the business mutation rolled back. |
| SMTP/Resend unavailable | Durable outbox retries with bounded backoff; terminal rows become `DEAD`. | Repair provider configuration, reconcile acceptance IDs, and replay through an approved operator procedure. |
| Failure after SMTP acceptance | A retry may duplicate because SMTP has no portable idempotency. | Reconcile provider logs/message IDs; do not mark inbox delivery. |
| Unknown JWT `kid` | Validators refresh JWKS and reject if still unknown. | Check rotation propagation and issuer; never bypass signature or token-class checks. |
| Compromised refresh/OAuth family | Replay revokes the whole family immediately inside AuthKit. | Investigate related audit events and require reauthentication. |

## Backup and restore

Back up PostgreSQL consistently and Redis AOF/RDB according to the chosen RPO. Encrypt before off-host transfer, restrict restore credentials, and record checksums. A release proof requires restoration onto a clean host, Flyway validation, login/session behavior checks, audit/outbox row reconciliation, Redis failover behavior, and documented actual RPO/RTO; copying files on the source host is not proof.

The supplied checks deliberately restore into isolated clean containers. PostgreSQL roles are recreated from the versioned golden init script and current mounted secrets; the database dump therefore does not export reusable password hashes. Example after identifying the exact Compose container and a protected backup directory:

```sh
AUTHKIT_BACKUP_DIR=/secure/authkit-backups \
AUTHKIT_POSTGRES_CONTAINER=authkit-golden-postgres-1 \
deploy/scripts/backup-postgres.sh

AUTHKIT_BACKUP_DIR=/secure/authkit-backups \
AUTHKIT_SECRETS_DIRECTORY=/secure/authkit-secrets \
deploy/scripts/restore-postgres-check.sh

AUTHKIT_BACKUP_DIR=/secure/authkit-backups \
deploy/scripts/restore-redis-check.sh
```

Create the Redis RDB with an authenticated `redis-cli --rdb`, store it as `authkit-redis-<UTC>.rdb`, and place its relative-name checksum beside it as `.rdb.sha256`. Encrypt and copy both database backups off-host after local verification. A clean-container check is useful evidence but does not itself prove off-host storage, production RPO/RTO, or a clean-host disaster recovery exercise.

## Key and secret rotation

Introduce a new RSA signing key and `kid`, retain the previous public key for at least the maximum issued-token lifetime, verify a downstream JWKS consumer refreshes, then revoke/remove the old key. Rotate worker, Redis, database, provider, audit-pepper, and MFA-encryption secrets with their documented previous-key windows where supported. Changing an HMAC/encryption root without a migration plan may invalidate lookup or decryptability; rehearse first.

## Capacity and release proof

Run mixed authenticated traffic, hostile bursts, and a soak of at least four hours on the declared 2-vCPU/4-GiB reference class. Record commit, image digest, configuration without secrets, data shape, p50/p95/p99, throughput, errors, CPU, memory, GC, database/Redis saturation, Argon2 queueing, and outbox backlog. Estimates and mock-only results are not evidence. External Google/OIDC, SMTP/Resend, TLS topologies, external OAuth client/conformance, downstream JWKS, alert routing, clean restore, and off-host backup remain `NOT PROVEN` until actually executed.
