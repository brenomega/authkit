# Deployment Tiers

Date: 2026-06-05

This document turns the cost-reduction strategy into deployable AuthKit tiers. The cost and user ranges are planning envelopes from `docs/strategy/authkit-cost-model.md`; they are not measured production SLOs. Prompt 3, or an equivalent targeted proof pass, must replace these estimates before a production commitment.

These tiers are integrator-neutral. Wavern is the first concrete target, but the same deployment model can be used by any system that consumes AuthKit as an authentication engine.

## Current-Code Truths

- PostgreSQL is mandatory.
- Redis is mandatory for the standard multi-instance-capable token backend.
- `AUTH_TOKEN_STORAGE_BACKEND=jdbc` is now available only for explicit single-instance PostgreSQL-only deployments with `AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE=true`.
- RabbitMQ is optional when `AUTH_EMAIL_OUTBOX_DISPATCH_MODE=direct`.
- PostgreSQL-only token storage is a constrained simplification tier, not a horizontal-scaling tier.
- CSRF, CORS, audit logging, session-bound access tokens, and Argon2 production floors must stay enabled in public deployments.

## Tier Table

| Tier | Current support | Monthly cost before taxes | Registered users | DAU assumption | Deployment shape |
| --- | --- | --- | --- | --- | --- |
| Tier 00E: Existing-Host Sidecar | Supported with constraints | `$0-$5 incremental` | `1-100` | `1-20` | Existing host spare capacity, isolated PostgreSQL, isolated Redis, direct email, no RabbitMQ |
| Tier 00H: Cost-Optimized Micro VPS | Supported with provider caveats | `$5.99-$12.39` | `1-100` | `1-20` | One low-cost VPS, local PostgreSQL, local Redis, direct email, no RabbitMQ |
| Tier 0S: Solo VPS Current-Code | Supported now | `$14.40-$22.60` | `1-500` | `1-100` | One small VPS, local PostgreSQL, local Redis, direct email, no RabbitMQ |
| Tier 1S: Larger Solo VPS Current-Code | Supported now | `$28.80-$35.20` | `501-1,500` | `101-300` | One larger VPS, local PostgreSQL, local Redis, direct email, no RabbitMQ |
| Tier 2M: Managed-Light Current-Code | Supported now | `$54.00-$79.00` | `1,501-7,500` | `301-1,500` | App VPS, managed PostgreSQL, managed/serverless Redis, direct email, no RabbitMQ |
| Tier 3R: Resilient Direct-Email | Supported now | `$103.00-$183.00` | `7,501-25,000` | `1,501-5,000` | Two app instances, managed PostgreSQL, managed Redis, direct email, optional lightweight queue |
| Tier 4F: Full Production Baseline | Supported, proof pending | `$230.00-$400.00+` | `25,001-50,000+` | `5,001-10,000+` | App replicas, managed PostgreSQL, managed Redis, queue, orchestration, full observability |
| Tier 0P: PostgreSQL-Only Single-Instance | Supported with constraints | `$14.40-$22.60` | `1-300` | `1-60` | One VPS, JDBC token storage, no Redis, direct email |

## Selection Rules

Choose **Tier 00E** when the host system already pays for suitable infrastructure, can isolate PostgreSQL and Redis, has spare CPU/RAM, and accepts shared-fate risk for `<=100` registered users.

Choose **Tier 00H** when the hard cost ceiling is below `$10-$12/month`, the target is `<=100` registered users, and the chosen provider's region, data residency, support posture, and shared-vCPU behavior are acceptable.

Choose **Tier 0S** when the goal is HML, a demo, or a very small production pilot below `500` registered users and the business accepts single-instance maintenance windows.

Choose **Tier 1S** when the deployment must stay below roughly `$35/month`, has `501-1,500` registered users, and still accepts single-instance operation.

Choose **Tier 2M** when managed database backups, resource isolation, or managed Redis durability matter more than the sub-`$30` target.

Choose **Tier 3R** when single-instance downtime is not acceptable or rolling deploys are required.

Choose **Tier 4F** for general AuthKit-as-a-platform production, larger Wavern scale, RabbitMQ isolation, or strict operational observability.

Choose **Tier 0P** only when Redis is operationally unacceptable or paid managed Redis is the cost driver. It requires `AUTH_TOKEN_STORAGE_BACKEND=jdbc`, `AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE=true`, local-only abuse throttling risk acceptance, and a targeted production proof before public cutover.

Terminology guardrail: if `100 clients` means `100 companies` rather than `100 registered users`, size by the total user and DAU count. Do not map `100 companies` to Tier 00H automatically.

## Tier 0S Environment Template

Use `docs/env/tier-0s-solo-vps.env.example`.

Important defaults:

- `AUTH_EMAIL_OUTBOX_DISPATCH_MODE=direct`
- `AUTH_EMAIL_OUTBOX_PRESERVE_RABBIT_OBSERVABILITY=false`
- `DB_POOL_MAX_SIZE=5`
- `DB_POOL_MIN_IDLE=1`
- `SECURITY_ARGON2_MAX_CONCURRENT=0`
- `AUTH_CSRF_ENABLED=true`
- `AUTH_CORS_ENABLED=true`
- `AUTH_REGISTRATION_STEALTH_CONFLICTS=true`

The template intentionally keeps Redis enabled. RabbitMQ credentials are intentionally absent.

## Tier 0P PostgreSQL-Only Settings

Tier 0P removes Redis only for explicit single-instance deployments:

```properties
AUTH_TOKEN_STORAGE_BACKEND=jdbc
AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE=true
AUTH_TOKEN_STORAGE_JDBC_CLEANUP_DELAY_MS=300000
AUTH_TOKEN_STORAGE_JDBC_CLEANUP_LOCK_AT_MOST=PT5M
AUTH_TOKEN_STORAGE_JDBC_SESSION_CURSOR_TTL_SECONDS=300
AUTH_ABUSE_FAIL_CLOSED_HIGH_RISK=false
AUTH_EMAIL_OUTBOX_DISPATCH_MODE=direct
```

Do not use Tier 0P for app replicas. JDBC token storage persists refresh sessions, recovery tokens, MFA login challenges, session cursors, and OAuth revocations, but request-rate and lockout controls degrade to local-only enforcement without Redis.

## Tier 1S Environment Template

Use `docs/env/tier-1s-solo-vps-large.env.example`.

This tier keeps the same security posture as Tier 0S but increases JVM, Hikari, and direct-email worker headroom for a `4 GiB/2 vCPU` VPS.

## Direct Email Acceptance Checks

Run these checks before using Tier 00E, Tier 00H, Tier 0S, or Tier 1S in HML:

- Start AuthKit without RabbitMQ configured.
- Confirm the application chooses direct outbox mode.
- Confirm RabbitMQ health does not appear in readiness when `AUTH_EMAIL_OUTBOX_PRESERVE_RABBIT_OBSERVABILITY=false`.
- Register a user and confirm an email outbox row is created.
- Confirm registration, recovery, reset, and password-change emails are delivered or retried through the outbox.
- Confirm failed email delivery increments retry attempts and eventually reaches the terminal `DEAD` state.
- Run the full Maven regression suite before production pilot use.

## Production Pilot Gates

For Tier 00E, Tier 00H, Tier 0S, and Tier 1S, do not cut over until these are complete:

- Host firewall exposes only HTTP(S), controlled SSH, and required outbound provider traffic.
- PostgreSQL backup and restore drill succeeds.
- Redis persistence or accepted session-loss behavior is documented.
- TLS termination and forwarded-header handling are tested.
- CORS allowlist contains only the integrator and AuthKit production origins.
- CSRF cookie/header flow works from the integrator frontend.
- Argon2 saturation, Hikari wait time, Redis latency, outbox backlog, audit drops, and high-risk abuse fail-closed metrics are visible.
- Admin accounts require MFA or passkeys.

## No-Go Conditions

- Do not run Tier 00E, Tier 00H, Tier 0S, or Tier 1S for production if the integrator cannot tolerate maintenance-window downtime.
- Do not use Tier 00H for `100 client companies` unless total registered users remain inside the `1-100` envelope.
- Do not disable Redis outside explicit Tier 0P single-instance JDBC token storage.
- Do not use the logging email provider in production.
- Do not store AuthKit access or refresh tokens in browser localStorage.
- Do not accept first-party or ID tokens as integrator resource API bearer tokens.
- Do not relax Argon2 below the production validator floors.
