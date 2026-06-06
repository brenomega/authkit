# Tier 1S Solo VPS Runbook

## Who Should Use This Tier

Use Tier 1S for larger single-node deployments that still avoid Kubernetes and RabbitMQ by default.

## Who Should Not Use This Tier

Do not use this tier when the business requires zero-downtime maintenance, active-active availability, or independently scalable workers.

## Required Host Size

Use the Tier 1S estimates in `docs/strategy/authkit-cost-model.md`. Do not raise Hikari, Argon2 concurrency, or email worker counts without proof reports.

## Firewall Setup

Same as Tier 0S, with stronger operator restrictions and monitoring alerts enabled before public launch.

## Environment Setup

Use Redis token storage and direct email initially. Move to queue mode when email backlog or provider throttling proves direct workers are insufficient.

## Startup

```bash
cp deploy/compose/.env.redis-direct.example deploy/compose/.env.redis-direct
deploy/scripts/preflight-config.sh deploy/compose/.env.redis-direct
docker compose --env-file deploy/compose/.env.redis-direct -f deploy/compose/docker-compose.redis-direct.yml up -d --build
```

## Smoke Testing

Run the proof pack with load enabled in HML:

```bash
AUTHKIT_BASE_URL=https://auth-hml.example.com testing/proof/run-proof.sh --tier 1s --backend redis --email-provider smtp --load true
```

## Backup Setup

Use daily PostgreSQL backups, Redis RDB backups for session recovery evidence, and off-host encrypted retention.

## Restore Drill

Perform a restore drill before launch and after schema changes.

## Metrics Check

Track login p95, refresh p95, OAuth introspection p95, Hikari pending, Argon2 saturation, Redis command latency, and email backlog age.

## Rollback

Rollback requires the previous image and a database restore point if migrations are not backward compatible.

## No-Go Conditions

- Load proof fails provisional budgets.
- Hikari waits persist under normal traffic.
- Redis degradation alerts fire.
- Scheduler locks are not active.
