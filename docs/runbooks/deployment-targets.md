# Deployment Targets

## Redis Direct

Use `deploy/compose/docker-compose.redis-direct.yml` when AuthKit runs with PostgreSQL, Redis token storage, and direct email dispatch. This is the default low-cost shape for small deployments because Redis keeps session and rate-limit operations off PostgreSQL while avoiding RabbitMQ.

## JDBC Direct

Use `deploy/compose/docker-compose.jdbc-direct.yml` only for Tier 0P single-instance deployments where the absolute lowest monthly cost matters more than horizontal scaling. This mode removes Redis but makes PostgreSQL a hotter dependency.

## Queue Mode

Use `deploy/compose/docker-compose.queue.yml` when RabbitMQ-backed email delivery is required. This is safer for bursty email workloads but costs more memory and operational attention.

## Kubernetes

Use the `k8s/` manifests for multi-instance or managed cluster deployments. Kubernetes is not the cheapest path for fewer than roughly hundreds of active users unless the host system already runs there.

## Firewall Baseline

- Public: reverse proxy ports 80 and 443 only.
- Internal: AuthKit application port 8080 from the reverse proxy only.
- Private: PostgreSQL 5432 and Redis 6379 from AuthKit only.
- Private: RabbitMQ 5672 from AuthKit/workers only when queue mode is enabled.

## Target Selection

Select the smallest tier that supports the current measured workload and operational risk. Move up a tier when proof reports show latency, error, CPU, memory, database, Redis, email backlog, or audit durability limits are being approached.
