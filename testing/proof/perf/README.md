# Performance Proof Scaffolding

This directory contains repeatable performance probes and SQL query-plan checks. It does not replace HML load testing.

## Run Tagged Performance Probes

From the repository root:

```bash
./mvnw -Dspring.profiles.active=test -Dtest='*PerformanceTest' test
```

The probes use generous local budgets and are intended to catch obvious regressions. They are not production capacity proof.

## Run SQL Query Plans

1. Restore or seed a PostgreSQL database with representative data.
2. Connect with `psql`.
3. Run each file under `testing/proof/perf/sql/`.
4. Save `EXPLAIN (ANALYZE, BUFFERS)` output into the proof report.

Do not use H2 query timings as PostgreSQL evidence.

## Tune Hikari

1. Start with the tier baseline in `docs/proof/performance-baselines.md`.
2. Run smoke tests and a small mixed workload.
3. Watch Hikari active, idle, pending, timeout, and database CPU.
4. Increase the pool only if pending waits occur while PostgreSQL has spare CPU and I/O.
5. Reduce the pool if PostgreSQL saturates or context switching rises.

## Tune Argon2

1. Do not lower memory, iteration, or parallelism floors.
2. Use `SECURITY_ARGON2_MAX_CONCURRENT=0` for CPU-derived automatic sizing unless the tier requires a stricter cap.
3. Lower concurrency before lowering Argon2 strength.
4. Watch login p95 and `security.argon2.saturation` metrics.

## Tune Direct Email Workers

1. Start with one or two workers on small tiers.
2. Increase only when SMTP/provider latency is the bottleneck and CPU/DB remain healthy.
3. Keep automatic retries within provider idempotency windows.
4. Move to queue mode when direct workers create API latency, memory pressure, or provider throttling.

## Compare Redis And JDBC Token Storage

1. Run the same smoke and load profile against Redis and JDBC tiers.
2. Compare refresh p95, session-list p95, PostgreSQL CPU, Redis latency, Hikari pending, and error rate.
3. Use JDBC only for single-instance deployments.
4. Do not enable high-risk abuse fail-closed without Redis-backed abuse state.

## Unsafe Tuning

- Do not disable CSRF to improve refresh throughput.
- Do not weaken password hashing to improve login throughput.
- Do not increase Hikari until evidence shows it helps.
- Do not run Tier 0P with multiple AuthKit instances.
