# Deployment Modes

## Standalone Authentication Service

Run AuthKit behind a TLS-terminating ingress or gateway. The edge owns public CORS/TLS policy; AuthKit still enforces its origin firewall, explicit CORS allowlist, request limits, and bearer validation. PostgreSQL is mandatory. Redis is mandatory for standard shared token/rate-limit state; explicit single-instance deployments may use JDBC token storage without Redis. Email may use RabbitMQ queue dispatch or bounded direct dispatch.

For costed Wavern-oriented deployment tiers, see `docs/DEPLOYMENT_TIERS.md`.

## Embedded Authentication Module

Package AuthKit beside another service but retain distinct controller, security, persistence, and token boundaries. The host may own the origin firewall only when it provides equivalent trusted-proxy validation before requests reach AuthKit. Keep AuthKit's firewall enabled when that ownership cannot be demonstrated. Direct email is acceptable for a single process; queue mode is preferred when retries must survive process loss independently.

## Monolith

Use the same first-party token/session semantics even when protected business controllers share the process. Authorization remains server-side and tenant-bound. PostgreSQL remains the scheduler lock authority. Redis remains required for multi-replica live sessions and distributed abuse controls; JDBC token storage is single-instance only until a future proof validates otherwise. Never bypass JWT class checks because calls are in-process.

## Scheduled Jobs

Production requires `AUTH_SCHEDULER_DISTRIBUTED_LOCK_ENABLED=true` whenever email polling or retention is enabled. A single-instance dev/test deployment may disable it. Email polling uses a maximum ten-minute lock; retention uses at least one minute and at most two hours.

## Starting Sizes

These are conservative, unproven resilient-baseline sizes pending Prompt 3 load and chaos evidence. They are not the cheapest Wavern tiers. Tune from measured p95/p99 latency, Argon2 saturation, Hikari wait time, Redis latency, queue depth, and JVM pressure.

| Approximate users | App replicas | CPU / memory per replica | Hikari max | Redis | Notes |
| ---: | ---: | --- | ---: | --- | --- |
| 500 | 2 | 1 vCPU / 1 GiB | 10 | 1 small managed primary | Start Argon2 auto-sized; queue email |
| 5,000 | 2-3 | 2 vCPU / 2 GiB | 15 | Managed primary with replica | Set explicit Argon2 concurrency after measurement |
| 50,000 | 3-6 | 4 vCPU / 4 GiB | 20 | HA managed Redis | Dedicated PostgreSQL, queue workers, autoscale on latency/saturation |

`SECURITY_ARGON2_MAX_CONCURRENT=0` derives permits from CPU. Explicit values should fit both CPU and memory: concurrent permits multiplied by Argon2 memory must leave headroom for the JVM, request threads, and caches.
