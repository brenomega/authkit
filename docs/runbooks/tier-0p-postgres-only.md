# Tier 0P PostgreSQL-Only Runbook

## Who Should Use This Tier

Use Tier 0P when supporting up to a very small number of clients at the lowest possible infrastructure cost is more important than horizontal scaling.

## Who Should Not Use This Tier

Do not use Tier 0P for multiple AuthKit replicas, high credential-attack risk, high refresh volume, or strict availability requirements.

## Required Host Size

Use `docs/strategy/authkit-cost-model.md` as an unproven baseline. PostgreSQL is the token backend and will be the main bottleneck.

## Firewall Setup

Expose only the reverse proxy. PostgreSQL must be private. There is no Redis service in this tier.

## Environment Setup

The following values are mandatory:

```text
AUTH_TOKEN_STORAGE_BACKEND=jdbc
AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE=true
AUTH_ABUSE_FAIL_CLOSED_HIGH_RISK=false
```

Keep direct email worker counts low. Keep Hikari small until measured evidence proves a higher pool helps.

## Startup

```bash
cp deploy/compose/.env.jdbc-direct.example deploy/compose/.env.jdbc-direct
deploy/scripts/preflight-config.sh deploy/compose/.env.jdbc-direct
docker compose --env-file deploy/compose/.env.jdbc-direct -f deploy/compose/docker-compose.jdbc-direct.yml up -d --build
```

## Smoke Testing

```bash
AUTHKIT_BASE_URL=http://localhost:8080 testing/proof/run-proof.sh --tier 0p --backend jdbc --email-provider smtp
```

## Backup Setup

PostgreSQL backups are mandatory because token state, revocation state, users, audit, and outbox all live in one database.

## Restore Drill

Run `deploy/scripts/restore-postgres-check.sh` before accepting users. Do not skip this; a PostgreSQL-only tier has no second state store.

## Metrics Check

Watch Hikari active/pending connections, token storage query latency, session pagination latency, refresh rotation errors, and audit write failures.

## Rollback

Stop the single AuthKit instance, restore previous image/jar, and restore PostgreSQL from backup if a migration must be reversed.

## No-Go Conditions

- More than one AuthKit instance is planned.
- Preflight fails.
- PostgreSQL reaches sustained high CPU or Hikari pending waits during proof.
- Backups have not been restore-checked.
