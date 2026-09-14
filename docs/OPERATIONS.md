# Operations and incident response

[English](OPERATIONS.md) | [Português (Brasil)](OPERATIONS-ptBR.md)

English is authoritative when translations differ.

The operator owns host hardening, DNS/TLS, secrets, legal text, email content and deliverability, provider accounts, backups/off-host encryption, alert routing, capacity validation, upgrades, and incident decisions. AuthKit supplies health/metrics, audit primitives, bounded jobs, revocation APIs, and reproducible harnesses; it is not an external SIEM, mailbox, backup service, or compliance certification.

## Routine checks

- Probe `/actuator/health` through TLS and scrape `/actuator/prometheus` only from a trusted network with `X-Worker-Token`.
- Watch request errors/latency, Argon2 saturation, PostgreSQL pool, Redis failures, authentication failures, lockouts, refresh replay, audit persistence failures, outbox backlog/age/dead count, and retention outcomes.
- Treat `security_effects_outstanding > 0` for five minutes as critical and follow [security-effect reconciliation](runbooks/security-effect-reconciliation.md). PostgreSQL live-state enforcement keeps stale credentials denied while Redis cleanup retries.
- Use `GET /api/v1/admin/operations` for non-secret outbox acceptance counts and configured posture. Use the cursor-bounded security-event endpoint for investigations; export to an operator SIEM when required.
- Treat `ACCEPTED` as provider acceptance. Track inbox observation separately and never alert on acceptance as if it proved delivery.

## Failure policy

| Failure | Expected behavior | Operator action |
| --- | --- | --- |
| Redis unavailable | High-risk golden-path auth operations fail closed; existing offline JWT consumers remain bounded by access expiry. | Restore Redis, inspect saturation/network/auth, verify replay/session state, then test login/refresh/logout. |
| Redis unavailable after a committed credential mutation | The committed PostgreSQL `security_version` denies stale JWT/session/refresh state; a durable security-effect row retries physical Redis cleanup. | Follow the reconciliation runbook; never bypass live-state validation or manually mark the task complete. |
| PostgreSQL unavailable | Mutations and live-state checks fail; opaque 5xx responses avoid detail leakage. | Stop risky traffic, restore primary/connection pool, verify Flyway state and audit continuity. |
| Audit write unavailable | Critical boundary mutations abort and return unavailable. | Restore audit persistence before retrying; confirm the business mutation rolled back. |
| SMTP/Resend unavailable | Durable outbox retries with bounded backoff; terminal rows become `DEAD`. | Repair provider configuration, reconcile acceptance IDs, and replay through an approved operator procedure. |
| Failure after SMTP acceptance | SMTP has no portable protocol idempotency. The supported relay must demonstrate deduplication by AuthKit's stable Message-ID, including crash/reclaim retries. | Verify the relay's dedupe window and reconcile provider logs/message IDs; acceptance is not inbox delivery. A relay without this proof is not a supported release configuration. |
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
AUTHKIT_REDIS_CONTAINER=authkit-golden-redis-1 \
deploy/scripts/backup-redis.sh

AUTHKIT_BACKUP_DIR=/secure/authkit-backups \
deploy/scripts/restore-redis-check.sh
```

The Compose Redis backup mode runs authenticated `redis-cli --rdb` inside the unexposed Redis container, copies only the RDB to the protected backup directory, and removes the temporary container file. Remote mode instead accepts `REDIS_HOST`, `REDIS_PORT`, and `REDIS_PASSWORD`. Encrypt and copy both database backups off-host after local verification. A clean-container check is useful evidence but does not itself prove off-host storage, production RPO/RTO, or a clean-host disaster recovery exercise.

## Key and secret rotation

Upgrade note: migration V27 invalidates in-flight social redirect transactions
created before consent versions were bound to the transaction. Users must restart
those short-lived redirects after upgrade; no account or accepted-consent ledger
is deleted. V28 adds durable recovery activation and its JDBC retry receipts.

Introduce a new RSA signing key and `kid`, retain the previous public key for at least the maximum issued-token lifetime, verify a downstream JWKS consumer refreshes, then revoke/remove the old key. Rotate worker, Redis, database, provider and MFA-encryption secrets with their documented previous-key windows where supported. Audit pepper uses coordinated invalidation with no online overlap: follow [key rotation](runbooks/key-rotation.md), including maintenance, dependent-state invalidation and historical audit verification.

Recovery email remains `WAITING_ACTIVATION` until its durable security effect
activates the token. Redis failures retry automatically without extending token
expiry or recreating consumed tokens. Expired or superseded activation cancels the
unsent email as `CANCELLED`; the user may request a fresh recovery link. Monitor
`security_effects_outstanding` and the reconciliation alert. Completed effects use
`AUTH_SECURITY_EVENT_RETENTION_DAYS` and `AUTH_RETENTION_BATCH_SIZE` in the locked,
bounded retention job; pending, failed and processing effects are never purged.

## Capacity and release proof

Run mixed authenticated traffic, hostile bursts, and a soak of at least four hours on the declared 2-vCPU/4-GiB reference class. Record commit, image digest, configuration without secrets, data shape, p50/p95/p99, throughput, errors, CPU, memory, GC, database/Redis saturation, Argon2 queueing, and outbox backlog. Estimates and mock-only results are not evidence. External Google/OIDC, SMTP/Resend, TLS topologies, external OAuth client/conformance, downstream JWKS, alert routing, clean restore, and off-host backup remain `NOT PROVEN` until actually executed.
