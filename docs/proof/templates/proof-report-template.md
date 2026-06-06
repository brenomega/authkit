# AuthKit Proof Report

Do not paste secrets, raw tokens, passwords, reset links, private keys, or full environment files into this report.

## Summary

- Date:
- Operator:
- Branch:
- Commit:
- Dirty tree: yes/no
- Tier:
- Backend:
- Email provider:
- Go/no-go:

## Environment

- Host provider:
- Host size:
- CPU:
- Memory:
- Disk:
- JVM:
- Heap settings:
- PostgreSQL version:
- PostgreSQL plan:
- Redis version, if used:
- RabbitMQ version, if used:
- SMTP/Resend mode:
- Reverse proxy/TLS:

## Configuration

- Token backend:
- Hikari max:
- Argon2 memory/iterations/parallelism/max concurrent:
- Email outbox mode/workers:
- Scheduler lock mode:
- CSRF enabled:
- Refresh cookie secure:
- HIBP enabled:
- Abuse fail-closed enabled:

## Commands

```bash
# Paste commands, not secrets.
```

## Smoke Results

| Flow | Status | Notes |
| --- | --- | --- |
| Health and metrics |  |  |
| Register/confirm/login/refresh/logout |  |  |
| Password recovery/reset |  |  |
| MFA login |  |  |
| Session list/revoke |  |  |
| OAuth code/token/userinfo |  |  |
| Negative token contracts |  |  |

## Load Results

| Scenario | VUs | Duration | p50 | p95 | p99 | Error rate | Notes |
| --- | ---: | --- | ---: | ---: | ---: | ---: | --- |
| login-refresh |  |  |  |  |  |  |  |
| registration-recovery |  |  |  |  |  |  |  |
| mfa-login |  |  |  |  |  |  |  |
| session-pagination |  |  |  |  |  |  |  |
| oauth-token-introspection |  |  |  |  |  |  |  |
| mixed-auth-workload |  |  |  |  |  |  |  |

## Metrics

- HTTP 5xx:
- Hikari active:
- Hikari pending:
- JVM memory:
- Argon2 saturation:
- Audit drops:
- Audit fail-closed:
- Email retries:
- Email dead:
- Scheduler failures:
- Redis degradation:

## Incidents

- What failed:
- User-visible impact:
- Logs/metrics:
- Remediation:

## Unresolved Risks

- Risk:
- Business impact:
- Technical impact:
- Owner:
- Due date:

## Decision

- Go:
- No-go:
- Conditions:
