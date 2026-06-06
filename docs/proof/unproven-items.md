# Remaining Unproven Items

This file records proof items that are intentionally not claimed as complete evidence by the scaffolding work.

## Pending Live Evidence

- k6 load scripts were created, but `k6` is not installed in this workspace, so `k6 inspect` and load runs were not executed here.
- Docker Compose files were validated with `docker compose config`, but full stack startup was not executed.
- `PostgresMigrationTest` was invoked, but Testcontainers skipped all three cases because this sandbox cannot access `/var/run/docker.sock` (`Operation not permitted`).
- No production or HML smoke proof report has been produced yet.
- No measured tier capacity claim has been produced; performance baselines and budgets remain provisional.
- Chaos scripts were syntax-checked only; they require an approved local/HML proof window and `AUTHKIT_CHAOS_APPROVED=true`.

## Required Follow-Up

1. Install k6 in HML and inspect every script under `testing/proof/k6/`.
2. Run Redis-direct, JDBC-direct, and queue compose stacks in HML.
3. Run `PostgresMigrationTest` in CI or a developer environment with Testcontainers Docker access.
4. Produce one proof report per target tier using `docs/proof/templates/proof-report-template.md`.
5. Update `docs/proof/performance-baselines.md` only after measured reports exist.
