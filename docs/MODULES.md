# AuthKit Module Registry

Date: 2026-06-05

This registry makes cost-reduction choices explicit. AuthKit can be used by Wavern or any future integrator, but module presets must not weaken public authentication controls just to lower infrastructure cost.

Cost and user envelopes live in `docs/strategy/authkit-cost-model.md`. Deployment shapes live in `docs/DEPLOYMENT_TIERS.md`.

## Module Classes

| Class | Meaning | Production rule |
| --- | --- | --- |
| Safe infrastructure switch | Replaces a paid or heavy dependency with an equivalent safe path | May be disabled when the alternate path is implemented, tested, and validated |
| Security control | Protects users, sessions, data, or auditability | Must remain enabled in public production unless a documented compensating control exists |
| Optional implementation module | Adds a new backend or integration path | Must be implemented, tested, documented, and validator-gated before use |

## Registry

| Module | Class | Default | May disable in low-cost tiers | Required safeguards |
| --- | --- | --- | --- | --- |
| MFA | Security control | Enabled | No, except private/internal deployments with written risk acceptance | Keep recovery, disable, and enrollment flows audited; keep login challenge state one-time |
| Passkeys | Security control | Enabled | No, except private/internal deployments with written risk acceptance | Keep RP ID/origin validation strict; do not allow origin ports in production |
| OAuth/OIDC provider | Optional integration module | Enabled | Yes, when AuthKit is only first-party auth | Token classes must stay distinct; revocation must be durable for enabled OAuth tokens |
| Distributed rate limiting | Security control | Redis-backed when Redis exists, local fallback on loss | Not for multi-replica public production | Single-instance JDBC/no-Redis mode must be explicit and accept local-only rate limiting |
| Email outbox | Security control and reliability module | Enabled | No for public auth flows | Registration, recovery, reset, and password-change emails must be durable and retryable |
| RabbitMQ dispatch | Safe infrastructure switch | Queue mode by default | Yes | Use direct outbox dispatch; RabbitMQ readiness must not affect direct-mode startup |
| Async audit writer | Security control with async performance path | Enabled for noncritical events | No for critical events | Critical events must persist synchronously; noncritical drops must emit metrics and alerts |
| Retention scheduler | Compliance module | Enabled | Only when another documented retention executor owns the job | Use distributed ShedLock when scheduled jobs are enabled |
| CSRF | Security control | Enabled | No for browser-cookie flows | Refresh/logout and cookie-bound auth endpoints must require CSRF header validation |
| CORS | Security control | Enabled | No for browser integrations | Allowlist only concrete HTTPS integrator origins in production |
| Origin firewall | Security control | Enabled through trusted proxy/origin settings | No for public edge deployments | Keep proxy depth and trusted origins documented per deployment |
| Argon2 tuning | Security control and performance module | CPU-derived concurrency, production floors enforced | No below validator floors | Use `SECURITY_ARGON2_MAX_CONCURRENT=0` for auto-sizing or explicit safe caps |
| SMTP email provider | Optional implementation module | Disabled | Yes, provider choice is deployer-specific | Production requires host, credentials when auth is enabled, and TLS or SSL |
| JDBC token storage | Optional implementation module | Disabled | Enables Redis-free single-instance deployments | Must use row-locked rotation, one-time recovery/MFA consumes, bounded session pagination, and explicit single-instance validation |

## Presets

| Preset | Tier | May disable | Must keep | Validator ownership |
| --- | --- | --- | --- | --- |
| `tier-00e-existing-host-sidecar` | Tier 00E | RabbitMQ, Kubernetes, managed services | PostgreSQL, Redis, CSRF, CORS, audit, outbox, Argon2 floors, MFA/passkeys for admin accounts | Reject logging email provider, weak secrets, relaxed CSRF/CORS, weak Argon2, missing Redis password |
| `tier-00h-cost-optimized-micro-vps` | Tier 00H | RabbitMQ, Kubernetes, managed services, oversized pools | Local PostgreSQL, local Redis, direct outbox email, CSRF, CORS, audit, Argon2 floors | Same as Tier 00E plus strict single-instance operational notes |
| `tier-0s-solo-vps` | Tier 0S | RabbitMQ, Kubernetes, managed services, high Hikari pool sizes | PostgreSQL, Redis, direct outbox email, CSRF, CORS, audit, Argon2 floors | Direct email timeout checks, scheduler lock checks, Redis credential validation |
| `tier-1s-solo-vps-large` | Tier 1S | RabbitMQ, Kubernetes, managed services | PostgreSQL, Redis, direct outbox email, CSRF, CORS, audit, Argon2 floors | Same as Tier 0S with larger pool/worker settings |
| `tier-2m-managed-light` | Tier 2M | RabbitMQ, Kubernetes | Managed PostgreSQL, managed Redis/Valkey, direct outbox email, security controls | Validate managed-service secrets and direct email timing |
| `tier-3r-resilient-direct` | Tier 3R | RabbitMQ if direct mode remains sufficient | Multi-instance app, shared PostgreSQL, shared Redis/Valkey, distributed locks, security controls | Reject no-Redis multi-replica operation |
| `tier-4f-full-production` | Tier 4F | Nothing by default without proof | Shared durable dependencies, queue or equivalent worker isolation, full observability, security controls | Full production validator plus Prompt 3 proof gates |
| `tier-0p-postgres-only` | Tier 0P | Redis | PostgreSQL JDBC token state, direct outbox email, local-only rate limiting risk acceptance, security controls | Require `AUTH_TOKEN_STORAGE_BACKEND=jdbc` and explicit single-instance mode; reject accidental multi-replica/no-Redis use |

## Non-Negotiable Public Production Controls

- Do not disable CSRF for browser refresh/logout flows.
- Do not disable CORS allowlist validation.
- Do not use the logging email provider.
- Do not lower Argon2 memory, iteration, or parallelism below production floors.
- Do not run multi-replica AuthKit without shared Redis or a proven shared token-state replacement.
- Do not disable security audit persistence for critical events.
- Do not use OAuth/OIDC access tokens without durable revocation.

## Preset Selection

Use the smallest preset whose user envelope, availability risk, and dependency ownership match the deployment. Tier 00E and Tier 00H are cheaper than Tier 0S only because of existing capacity or a cheaper VPS provider; they do not authorize weaker authentication controls.

Tier 0P is an operational simplification preset. It is useful when Redis is forbidden or managed Redis is the cost driver. It is not automatically cheaper than Tier 0S when Redis runs locally on the same VPS.
