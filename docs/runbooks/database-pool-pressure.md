# Sustained PostgreSQL pool wait

Capture `hikaricp_connections_active`, `idle`, `pending`, acquisition latency and PostgreSQL `pg_stat_activity`. Identify leaked/slow transactions and database saturation before changing pool size. Cancel only a precisely identified unsafe query under the operator change procedure. Verify pending connections return to zero and stay there for ten minutes, then repeat readiness and mixed-workload smoke tests.
