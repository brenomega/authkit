# AuthKit Runbooks

These runbooks make deployment and proof work repeatable. They are operational references, not marketing material.

## Start Here

1. Pick a deployment target in [deployment-targets.md](deployment-targets.md).
2. Review the matching tier runbook.
3. Prepare secrets and key files outside Git.
4. Run `deploy/scripts/preflight-config.sh`.
5. Start AuthKit.
6. Run the smoke and proof scripts in [docs/proof](../proof/README.md).
7. Configure backups and perform a restore check.

## Tier Runbooks

- [Tier 00H micro VPS](tier-00h-micro-vps.md)
- [Tier 0S solo VPS](tier-0s-solo-vps.md)
- [Tier 1S solo VPS](tier-1s-solo-vps.md)
- [Tier 0P PostgreSQL-only](tier-0p-postgres-only.md)

## Non-Negotiable Rules

- Do not expose PostgreSQL to the public internet.
- Do not expose Redis to the public internet.
- Do not deploy with `CHANGE-ME` values.
- Do not use the logging email provider in production.
- Do not disable CSRF for browser refresh/logout.
- Do not run Tier 0P with multiple AuthKit instances.
- Do not treat estimates as measured capacity.
