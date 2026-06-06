# Health And Readiness Runbook

## Purpose

Health checks prove AuthKit is reachable. Readiness checks prove dependencies and critical flows are safe enough to accept traffic.

## Basic Health

```bash
curl -fsS "${AUTHKIT_BASE_URL}/actuator/health"
```

Expected result: HTTP 200. Details may be hidden unless the caller is authorized.

## Metrics Snapshot

```bash
curl -fsS "${AUTHKIT_BASE_URL}/actuator/prometheus" > target/authkit-prometheus.txt
```

Check at minimum:

- HTTP 5xx rate.
- Hikari active and pending connections.
- Argon2 saturation.
- Audit dropped/fail-closed metrics.
- Email retry/dead metrics.
- Redis degradation metrics for Redis tiers.
- Scheduler failure metrics.

## Smoke Tests

Run local or HML smoke tests:

```bash
AUTHKIT_BASE_URL=http://localhost:8080 testing/proof/run-proof.sh --tier 0s --backend redis --email-provider smtp
```

Do not run proof scripts against production unless an approved proof window exists and `ALLOW_PRODUCTION_PROOF=true` is intentionally set.

## Diagnostics

```bash
AUTHKIT_BASE_URL=http://localhost:8080 deploy/scripts/collect-diagnostics.sh
```

Review masked diagnostics before sharing them. The masking routine is a guardrail, not a substitute for human review.

## No-Go Conditions

- Health endpoint fails.
- PostgreSQL is unreachable.
- Redis is unreachable for Redis-backed tiers.
- Scheduler locks are disabled while scheduled jobs are enabled.
- Critical audit writes fail.
- Email outbox has terminal dead messages during a release.
- Any production env value still contains `CHANGE-ME`.
