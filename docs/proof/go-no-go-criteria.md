# Go/No-Go Criteria

## Go

Approve a tier for the next environment only when all of the following are true:

- Preflight passes.
- Smoke scripts pass.
- Negative token contracts pass.
- No critical audit persistence failures occur.
- No dead email messages remain after proof.
- Hikari pending waits are not sustained.
- Argon2 saturation is not sustained.
- Redis degradation does not occur on Redis-backed tiers.
- Backups are created and restore-checked.
- Any load test p95 values remain within the provisional budget in `performance-budgets.md`.

## Conditional Go

Proceed only with written risk acceptance when:

- A noncritical smoke script is not applicable to the selected tier.
- A chaos script cannot run because Docker or HML permissions are unavailable.
- Load testing is deferred for a private/internal pilot with very low user counts.

The proof report must name the compensating control and owner.

## No-Go

Stop deployment when any of the following happens:

- Production-like env contains `CHANGE-ME`.
- CSRF is disabled for browser refresh/logout.
- Refresh cookies are insecure outside local development.
- PostgreSQL or Redis is publicly exposed.
- Tier 0P is configured with multiple AuthKit instances.
- Critical audit fail-closed events occur.
- Token class negative tests fail.
- Session revocation/logout-all does not invalidate first-party access.
- Password reset or confirmation links leak tokens through query strings.
- Backups cannot be restore-checked.
