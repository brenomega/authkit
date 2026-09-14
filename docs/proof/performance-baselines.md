# AuthKit v0.1 performance baseline

[English](performance-baselines.md) | [Português (Brasil)](performance-baselines-ptBR.md)

English is authoritative when translations differ. This baseline is bound to the `v0.1.0-rc.1` release line and the immutable candidate identity recorded in the final consolidated audit; it is not a capacity promise for other hardware or workloads.

## Reference tier and immutable acceptance thresholds

| Dimension | v0.1 reference |
| --- | --- |
| Host | Linux, 2 vCPU, 4 GiB RAM |
| Co-location | AuthKit, PostgreSQL 17 and Redis 7 on one host |
| JVM | Java 21; maximum heap 1 GiB |
| Workload | Mixed lifecycle traffic plus a controlled hostile burst |
| Soak | At least 4 continuous hours |
| Login latency | p95 <= 1,200 ms |
| Refresh latency | p95 <= 300 ms |
| OAuth introspection latency | p95 <= 300 ms |
| Session-list latency | p95 <= 400 ms |
| Integrity | Zero accepted replay, integrity error or critical audit loss |
| Pool | No sustained Hikari wait |
| Email | No unresolved backlog older than five minutes |

These values come from Release Specification section 23 and must not be weakened to make a failed run green. A run report records UTC interval, candidate source SHA-256 and OCI digest, host/cgroup limits, complete configuration, workload mix, duration, request counts, p50/p95/p99, error classes, CPU/memory/JVM/DB/Redis/Hikari saturation, audit/email integrity queries and limitations. Registered-user or DAU examples are planning inputs only.

## Reproduction

Use `testing/proof/k6/mixed-auth-workload.js` for the steady mix and the focused k6 profiles for lifecycle isolation. Execute the hostile burst without disabling Redis-backed abuse controls or changing password hashing. Run the SQL probes in `testing/proof/perf/sql/` on the populated PostgreSQL database and attach `EXPLAIN (ANALYZE, BUFFERS)` output. Compare Redis and JDBC token stores only as separate, explicitly labelled runs. AuthKit v0.1's release-gated golden topology is single-instance; multi-instance layouts remain unsupported planning material.

The reference steady run defaults to four VUs paced to an aggregate `K6_TARGET_RPS=0.8`, below the normative 60-requests/minute budget for its single non-spoofed client address. Their initial password logins are staggered by four seconds to respect the bounded Argon2 admission pool before steady traffic begins. Record any override. Higher aggregate offered load requires independent real client addresses; it is not valid to weaken the limiter or spoof forwarding headers. The separate hostile burst deliberately crosses the boundary and must remain fail-closed.

The final consolidated audit is the evidence index. Until its Gate 10 record contains a complete run satisfying every row above against one frozen candidate, this file defines a target baseline—not a successful measurement.
