# AuthKit Proof Pack

The proof pack records evidence that a selected AuthKit deployment tier behaves correctly before it is trusted with real users.

## Tier Matrix

Capacity ranges must come from `docs/strategy/authkit-cost-model.md`. The rows below are proof targets, not measured claims.

| Tier | Token backend | Email mode | Typical proof target | Current status |
| --- | --- | --- | --- | --- |
| 00H Redis direct | Redis | Direct SMTP/Resend | Micro VPS baseline from the cost model | Estimated, unproven |
| 0S Redis direct | Redis | Direct SMTP/Resend | Solo VPS baseline from the cost model | Estimated, unproven |
| 1S Redis direct | Redis | Direct or queue if proven necessary | Larger solo VPS baseline from the cost model | Estimated, unproven |
| 0P JDBC direct | PostgreSQL | Direct SMTP/Resend | Lowest-cost single-instance baseline from the cost model | Estimated, unproven |

## Proof Commands

Smoke only:

```bash
AUTHKIT_BASE_URL=http://localhost:8080 testing/proof/run-proof.sh --tier 0s --backend redis --email-provider smtp
```

Smoke plus load:

```bash
AUTHKIT_BASE_URL=http://localhost:8080 testing/proof/run-proof.sh --tier 1s --backend redis --email-provider smtp --load true
```

Chaos scripts are opt-in and refuse production-looking hosts by default:

```bash
AUTHKIT_BASE_URL=http://localhost:8080 COMPOSE_FILE=deploy/compose/docker-compose.redis-direct.yml testing/proof/run-proof.sh --tier 0s --backend redis --email-provider smtp --chaos true
```

## Required Evidence

Every proof report should include:

- Git commit and dirty status.
- Tier, backend, host size, JVM heap, Hikari size, email mode, and token backend.
- Smoke script results.
- Load results when the tier claims user capacity.
- Metrics snapshots before and after proof.
- Dependency failure behavior when chaos scripts are run.
- Go/no-go decision and unresolved risks.

Never paste secrets, raw passwords, refresh tokens, access tokens, reset tokens, or private keys into proof reports.
