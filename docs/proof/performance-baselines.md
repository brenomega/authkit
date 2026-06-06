# Performance Baselines

These baselines are starting points for proof runs. They are not measured capacity claims unless a row cites a proof report.

| Tier | Host size | JVM heap | Hikari max | Token backend | Email mode | Expected bottleneck | Status |
| --- | --- | --- | ---: | --- | --- | --- | --- |
| 00H | See cost model micro VPS row | 256-512 MiB | 2-3 | Redis or JDBC | Direct | CPU during Argon2 and email dispatch | estimated |
| 0S | See cost model solo VPS row | 512 MiB-1 GiB | 3-5 | Redis | Direct | Argon2 concurrency, Redis availability, SMTP latency | estimated |
| 1S | See cost model large solo VPS row | 1-2 GiB | 5-10 | Redis | Direct initially | DB connections, email backlog, Redis latency | estimated |
| 0P | See cost model PostgreSQL-only row | 384-768 MiB | 2-3 | JDBC | Direct | PostgreSQL token hot paths and Argon2 CPU | estimated |

## Evidence Rules

- `estimated`: derived from configuration and cost model only.
- `operator-provided`: observed manually but not reproduced by proof scripts.
- `measured`: backed by a proof report in `docs/proof/reports/` or external evidence attached to a ticket.
- `unknown`: no credible basis.

Do not edit deployment tier user counts based only on local H2 timings, laptop runs, or a single happy-path smoke test.
