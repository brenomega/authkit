# Tier 00H Micro VPS Runbook

## Who Should Use This Tier

Use Tier 00H for demos, prototypes, internal testing, or very small host systems where cost is the primary constraint and downtime can be tolerated.

## Who Should Not Use This Tier

Do not use this tier for regulated data, high availability, high email volume, or customer-facing production without explicit risk acceptance.

## Required Host Size

Use the host sizing from `docs/strategy/authkit-cost-model.md`. Treat it as an unproven baseline until a proof report exists for the exact host.

## Firewall Setup

Expose only the reverse proxy. PostgreSQL, Redis, and AuthKit's direct port must not be public.

## Environment Setup

Start from `deploy/compose/.env.redis-direct.example` or `deploy/compose/.env.jdbc-direct.example`. Replace every `CHANGE-ME`. Keep `SECURITY_ARGON2_MAX_CONCURRENT=1` unless proof evidence supports a change.

## Startup

```bash
cp deploy/compose/.env.redis-direct.example deploy/compose/.env.redis-direct
deploy/scripts/preflight-config.sh deploy/compose/.env.redis-direct
docker compose --env-file deploy/compose/.env.redis-direct -f deploy/compose/docker-compose.redis-direct.yml up --build
```

## Smoke Testing

Run:

```bash
AUTHKIT_BASE_URL=http://localhost:8080 testing/proof/run-proof.sh --tier 00h --backend redis --email-provider smtp
```

## Backup Setup

Set `AUTHKIT_BACKUP_DIR` and run `deploy/scripts/backup-postgres.sh`. Run `deploy/scripts/backup-redis.sh` only when Redis mode is enabled.

## Restore Drill

Run `deploy/scripts/restore-postgres-check.sh` after the first backup and after backup configuration changes.

## Metrics Check

Capture `/actuator/prometheus` before and after smoke tests. Watch Hikari pending connections, Argon2 saturation, and email backlog age.

## Rollback

Stop AuthKit, restore the previous jar or image, and restart. If a migration was applied, restore from the verified backup rather than attempting manual schema edits.

## No-Go Conditions

- Any `CHANGE-ME` remains.
- Redis or PostgreSQL is reachable from the internet.
- Proof smoke tests fail.
- Backups have not been restore-checked.
