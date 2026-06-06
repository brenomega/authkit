# Tier 0S Solo VPS Runbook

## Who Should Use This Tier

Use Tier 0S for small production pilots or low-traffic systems that need Redis-backed sessions and direct email without RabbitMQ.

## Who Should Not Use This Tier

Do not use this tier for high availability, heavy credential-attack exposure without external controls, or large user bases until Prompt 3-style load and chaos proof exists.

## Required Host Size

Use `docs/strategy/authkit-cost-model.md` for the current estimated range. Verify with `docs/proof/templates/proof-report-template.md` before raising supported-user claims.

## Firewall Setup

Allow public traffic only through TLS reverse proxy. PostgreSQL and Redis stay private. Restrict SSH to operator IPs.

## Environment Setup

Use Redis backend:

```text
AUTH_TOKEN_STORAGE_BACKEND=redis
AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE=false
AUTH_EMAIL_OUTBOX_DISPATCH_MODE=direct
```

Replace every secret. Keep CSRF and secure refresh cookies enabled.

## Startup

```bash
cp deploy/compose/.env.redis-direct.example deploy/compose/.env.redis-direct
deploy/scripts/preflight-config.sh deploy/compose/.env.redis-direct
docker compose --env-file deploy/compose/.env.redis-direct -f deploy/compose/docker-compose.redis-direct.yml up -d --build
```

## Smoke Testing

```bash
AUTHKIT_BASE_URL=https://auth.example.com testing/proof/run-proof.sh --tier 0s --backend redis --email-provider smtp
```

Set `ALLOW_PRODUCTION_PROOF=true` only during an approved production proof window.

## Backup Setup

Schedule `authkit-backup.timer.example` or an equivalent cron. Keep encrypted off-host copies.

## Restore Drill

Run the restore check weekly for pilots and before every major release.

## Metrics Check

Check Hikari, Redis degradation, email retry/dead counts, scheduler failures, audit fail-closed events, and HTTP p95 latency.

## Rollback

Keep the previous image or jar and the previous env file. If the release includes a migration, prepare a database restore plan before deployment.

## No-Go Conditions

- Preflight fails.
- Redis is degraded before deployment.
- Critical audit fail-closed events appear during smoke tests.
- Email dead messages appear during smoke tests.
