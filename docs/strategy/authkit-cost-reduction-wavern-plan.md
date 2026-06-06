# AuthKit Cost Reduction And Integration Plan

Date: 2026-06-05

## Objective

Reduce AuthKit's infrastructure cost enough to make it viable as an authentication engine for Wavern and future integrator systems, while preserving the security gains from Prompts 1, 2, and 2.5.

Wavern is the first concrete integration profile, not the only intended consumer. Deployment tiers, cost envelopes, token boundaries, and module decisions must remain reusable for any host system that wants to consume AuthKit as an external authentication service or embed it behind a monolith boundary.

This plan updates the earlier cost-reduction direction against the current post-Prompt 2.5 AuthKit codebase. It also fixes the previous ambiguity around deployment tiers: every tier now has a monthly cost envelope, a registered-user envelope, and explicit selection criteria.

The detailed cost model is maintained in `docs/strategy/authkit-cost-model.md`. This plan must not be updated with new tiers unless that document is updated at the same time.

## Executive Recommendation

Proceed with cost reduction before full Prompt 3, but do not start from the old `$30-60/month` managed-service tier.

Use AuthKit as an external authentication service. For the current Wavern HML goal, start with the smallest safe tier that matches the real user count and provider constraints:

- **Tier 00E: Existing-Host Sidecar** when the host system already has spare compute, isolated PostgreSQL, isolated Redis, and accepts shared-fate risk. Incremental infrastructure cost can be `$0-$5/month`.
- **Tier 00H: Cost-Optimized Micro VPS** when the target is up to `100 registered users` and a low-cost provider such as Hetzner is acceptable. Expected cost is `$5.99-$12.39/month` before tax, depending on region.
- **Tier 0S: Solo VPS Current-Code** when provider-neutral sizing is preferred or the target is up to `500 registered users`.

Tier 0S remains the safest provider-neutral low-cost baseline:

- One VPS runs AuthKit, PostgreSQL, and Redis.
- Email uses the existing durable PostgreSQL outbox in `direct` dispatch mode.
- RabbitMQ is disabled.
- Kubernetes is not used.
- Redis remains enabled because current AuthKit production token/session safety still depends on it.

Expected Tier 0S cost: **$14.40-$22.60/month before taxes**, supporting **1-500 registered users** under the workload assumptions in `docs/strategy/authkit-cost-model.md`.

Terminology guardrail: `100 clients` must be interpreted as `100 registered users` unless a separate tenant/user ratio is supplied. `100 client companies` could mean hundreds or thousands of users and should not be mapped to Tier 00H automatically.

The previous "Tier A vs Tier B" framing was unclear. The corrected rule is:

- **Self-hosted Redis on the same VPS is not a meaningful monthly-cost driver.** Removing Redis mainly reduces operational complexity, not the cloud bill.
- **Managed Redis is a cost driver.** Avoiding managed Redis can save roughly `$10-$15/month` at small scale, or more with HA plans.
- **PostgreSQL-only token storage is now an explicit single-instance simplification module.** It is still not the cheapest safe first move on one VPS because local Redis adds little monthly cost; it matters most when managed Redis would be a separate paid service or Redis is operationally forbidden.

## Current-State Comparison

| Area | Cost plan expectation | Current AuthKit state | Decision |
| --- | --- | --- | --- |
| Prompt 2.5 | Needed before integration | Complete in code/docs/CI according to `docs/audits/final_audit.md` | No need to run full Prompt 3 before cost work |
| RabbitMQ elimination | Needed | Already supported by `AUTH_EMAIL_OUTBOX_DISPATCH_MODE=direct` | Disable RabbitMQ in Tier 0S, Tier 1S, and Tier 2M |
| Email provider abstraction | Needed | `EmailProvider` SPI exists; Resend, SMTP, and logging providers exist | Keep Resend first; use SMTP when an integrator needs cheaper/provider-owned email |
| Durable outbox | Needed | Present; direct and queue modes use same durable outbox states | Keep enabled in every tier |
| PostgreSQL | Required | Required and core | Keep mandatory |
| Redis | Candidate for elimination | Standard backend remains Redis; JDBC token storage is available for explicit single-instance no-Redis tiers | Keep Redis for scalable tiers; use JDBC only with Tier 0P constraints |
| Distributed scheduler locks | Missing in old analysis | Implemented with ShedLock/PostgreSQL DB time | Keep when jobs are enabled |
| Deployment modes | Needed | `docs/DEPLOYMENT_MODES.md` documents standard Redis mode and explicit single-instance JDBC mode | Keep deployment-tier docs aligned with code-supported presets |
| Module docs/presets | Needed | Not yet formalized | Add module/tier docs before code-heavy Tier 0P |
| Generic integrator boundary | Needed | `docs/INTEGRATOR.md` exists; Wavern-specific spec exists under `docs/integration/` | Keep generic docs separate from Wavern-specific claims |
| Wavern JWT bridge | Needed for first integration | Not implemented | Investigate before frontend migration |
| Prompt 3 proof | Needed for production | Not done | Run a targeted proof against the selected tier before production cutover |

## Costed Deployment Tiers

These are planning envelopes, not measured production capacity claims. They are precise enough to choose the next engineering step, but Prompt 3 or an equivalent targeted proof is still required before production cutover.

| Tier | Current support | Infrastructure | Monthly cost before taxes | Registered users | DAU assumption | Selection criteria |
| --- | --- | --- | --- | --- | --- | --- |
| Tier 00E: Existing-Host Sidecar | Supported with constraints | Existing host spare capacity, isolated PostgreSQL, isolated Redis, direct outbox email, no RabbitMQ | `$0-$5 incremental` | `1-100` | `1-20` | Choose only when the host system already pays for suitable infrastructure and accepts shared-fate risk |
| Tier 00H: Cost-Optimized Micro VPS | Supported with provider caveats | 1 low-cost VPS with local PostgreSQL, local Redis, direct outbox email, no RabbitMQ | `$5.99-$12.39` | `1-100` | `1-20` | Choose when cost ceiling is below `$10-$12/month`, regional latency/compliance are acceptable, and single-instance risk is accepted |
| Tier 0S: Solo VPS Current-Code | Supported now | 1 small VPS, local PostgreSQL, local Redis, direct outbox email, no RabbitMQ | `$14.40-$22.60` | `1-500` | `1-100` | Choose when the hard cost ceiling is below `$25/month`, one instance is acceptable, and the deployment is HML or pilot production |
| Tier 1S: Larger Solo VPS Current-Code | Supported now | 1 larger VPS, local PostgreSQL, local Redis, direct outbox email, no RabbitMQ | `$28.80-$35.20` | `501-1,500` | `101-300` | Choose when Tier 0S hits memory/CPU pressure but managed services are still too expensive |
| Tier 2M: Managed-Light Current-Code | Supported now | App VPS, managed PostgreSQL, managed/serverless Redis, direct outbox email, no RabbitMQ | `$54.00-$79.00` | `1,501-7,500` | `301-1,500` | Choose when database backups, isolation, or Redis durability matter more than the sub-`$30` target |
| Tier 3R: Resilient Direct-Email | Supported now | 2 app instances, managed PostgreSQL, managed Redis/Valkey, direct outbox email, optional lightweight queue | `$103.00-$183.00` | `7,501-25,000` | `1,501-5,000` | Choose when uptime and horizontal scaling become more important than minimum cost |
| Tier 4F: Full Production Baseline | Supported but Prompt 3 proof pending | 2+ larger app nodes, managed PostgreSQL, managed Redis/Valkey, RabbitMQ or equivalent queue, orchestration, full observability | `$230.00-$400.00+` | `25,001-50,000+` | `5,001-10,000+` | Choose for general AuthKit-as-a-platform production or larger Wavern scale |
| Tier 0P: PostgreSQL-Only Single-Instance | Supported with constraints | 1 VPS, JDBC token storage, no Redis, direct outbox email | `$14.40-$22.60` | `1-300` | `1-60` | Choose only if operational simplicity or managed-Redis avoidance justifies single-instance/local-throttle risk |

Important correction: Tier 0P is not automatically cheaper than Tier 0S on a single VPS. It uses the same compute envelope and saves little or no cloud spend when Redis is local. Its value is simplification and fewer moving parts. It is financially useful mainly when the alternative is paid managed Redis.

## Tier Selection Rules

Use the smallest tier that satisfies all conditions below:

| Condition | Required tier |
| --- | --- |
| Existing host has spare capacity, isolated PostgreSQL/Redis, and accepts shared-fate risk; `<=100` registered users | Tier 00E |
| Hard cost ceiling below `$10-$12/month`; `<=100` registered users; provider region and shared-vCPU caveats accepted | Tier 00H |
| HML, demo, or pilot production; `<=500` registered users; accepts single-instance maintenance windows | Tier 0S |
| `501-1,500` registered users; still accepts single-instance maintenance windows | Tier 1S |
| Needs managed database backups, managed Redis, or better isolation from app memory pressure | Tier 2M |
| Needs two app instances or reduced downtime during deploys | Tier 3R |
| Needs RabbitMQ isolation, platform-level production observability, or broad AuthKit provider usage | Tier 4F |
| Wants to remove Redis completely | Tier 0P, but only with explicit single-instance JDBC token storage |

Hard no-go rules:

- Do not choose Tier 00E, Tier 00H, Tier 0S, or Tier 1S for production if the integrator cannot tolerate downtime during host or VPS maintenance.
- Do not use Tier 00H for `100 client companies` unless the total registered-user count and login workload still fit the `1-100` registered-user envelope.
- Do not choose Tier 0P for multi-replica deployments or without targeted proof of the selected single-instance deployment.
- Do not run multi-replica deployments without shared Redis or a proven shared token-state replacement.
- Do not reduce Argon2 security parameters below production validator floors to fit a cheaper machine.

## Module Cost Strategy

The modular cost-reduction approach is retained, but each module is classified as one of three types:

| Module type | Examples | Cost effect | Security rule |
| --- | --- | --- | --- |
| Safe cost switches | RabbitMQ queue dispatch, Kubernetes, managed Redis/DB, paid email provider, oversized Hikari pool | Direct monthly savings | Can be disabled when current code already supports an equivalent safe path |
| Security feature switches | MFA, passkeys, CSRF, CORS, origin firewall, audit logging, Argon2 floors | Usually small savings | Must not be disabled in public production unless a documented compensating control exists |
| Future implementation modules | Integrator-specific JWT bridge, SES provider, additional module presets | Potential savings or integration value | Requires code, tests, docs, and production validation before use |

This preserves the user's module idea without pretending that every feature can be relaxed safely. The cost win should come first from optional infrastructure, not from weakening authentication controls.

## Recommended Provider-Neutral Tier: Tier 0S

Target: Wavern HML, generic integrator demos, and very small production pilots when Tier 00E is unavailable and Tier 00H provider constraints are not acceptable.

Infrastructure:

- One VPS in the `2 GiB/1 vCPU` to `2 GiB/2 vCPU` class.
- AuthKit app.
- PostgreSQL on the same VPS.
- Redis on the same VPS.
- Resend or SMTP provider.
- Direct email dispatch.
- No RabbitMQ.
- No Kubernetes.

Required settings:

```properties
AUTH_EMAIL_OUTBOX_ENABLED=true
AUTH_EMAIL_OUTBOX_DISPATCH_MODE=direct
AUTH_EMAIL_OUTBOX_DIRECT_BATCH_SIZE=5
AUTH_EMAIL_OUTBOX_DIRECT_CORE_POOL_SIZE=1
AUTH_EMAIL_OUTBOX_DIRECT_MAX_POOL_SIZE=2
AUTH_EMAIL_OUTBOX_DIRECT_QUEUE_CAPACITY=25
AUTH_EMAIL_OUTBOX_PRESERVE_RABBIT_OBSERVABILITY=false
AUTH_EMAIL_PROVIDER_TYPE=resend
DB_POOL_MAX_SIZE=5
DB_POOL_MIN_IDLE=1
SECURITY_ARGON2_MAX_CONCURRENT=0
```

Security posture:

- Strong session-bound access tokens remain.
- Redis-backed sessions, recovery, MFA challenges, and revocation remain.
- Local plus Redis abuse controls remain.
- Email remains durable through PostgreSQL outbox.

Operational limits:

- Single-instance availability only.
- Backups, restore drills, firewalling, host hardening, and patch cadence become mandatory operator responsibilities.
- This tier is not approved for large public production until Prompt 3 measurements validate it.

## Implementation Plan

### Phase 0: Cost Model And Tier Documentation

Goal: remove ambiguity before code changes.

Tasks:

- Maintain `docs/strategy/authkit-cost-model.md` with current price references, formulas, assumptions, and tier ranges.
- Create `docs/DEPLOYMENT_TIERS.md` with:
  - Tier 00E: existing-host sidecar.
  - Tier 00H: cost-optimized micro VPS.
  - Tier 0S: solo VPS current-code.
  - Tier 1S: larger solo VPS current-code.
  - Tier 2M: managed-light current-code.
  - Tier 3R: resilient direct-email.
  - Tier 4F: full production baseline.
  - Tier 0P: future PostgreSQL-only.
- Add copy-pastable environment templates for Tier 0S and Tier 1S.
- Add Tier 00H and Tier 00E templates only after the target provider or host system is chosen, because their safe memory, backup, network, and isolation settings are provider/host-specific.
- Clearly label all unmeasured values as baselines pending Prompt 3.

Acceptance criteria:

- Operators can answer "Which tier is cheapest today?" accurately: Tier 00E when existing capacity is available; otherwise Tier 00H when its provider and single-instance constraints are acceptable; otherwise Tier 0S.
- Operators can answer "Is PostgreSQL-only cheaper today?" accurately: not on one VPS; it is a single-instance simplification module.
- Operators can answer "Can I run AuthKit without RabbitMQ?" accurately: yes, through direct email mode.
- Operators can answer "Can I run AuthKit without Redis?" accurately: yes, only through explicit single-instance JDBC token storage.

### Phase 1: Configuration-Only Cost Reduction

Goal: create a low-cost Wavern or generic integrator HML deployment using current AuthKit code.

Tasks:

- Configure `AUTH_EMAIL_OUTBOX_DISPATCH_MODE=direct`.
- Keep Redis enabled.
- Reduce Hikari defaults for Wavern HML: `DB_POOL_MAX_SIZE=5`, `DB_POOL_MIN_IDLE=1`.
- Keep production Argon2 minimums; do not go below `security.argon2.memory=19456`, `iterations=2`, `parallelism=1`.
- Keep `AUTH_CSRF_ENABLED=true` and `AUTH_CORS_ENABLED=true`.
- Keep `AUTH_REGISTRATION_STEALTH_CONFLICTS=true` in public environments.
- Use Tier 0S or Tier 1S templates for provider-neutral deployments.
- Create a Tier 00H template only after selecting the concrete low-cost VPS provider and region.
- Use Tier 00E only after verifying isolated database, Redis, host resource, firewall, backup, and rollback boundaries.

Acceptance criteria:

- AuthKit starts without RabbitMQ in direct email mode.
- Registration, recovery, reset, and password-change emails are delivered or retried through the outbox.
- RabbitMQ health does not affect readiness in direct mode.
- Existing full test suite remains green.

### Phase 2: Integrator Bridge Discovery

Goal: prove that a host system can consume AuthKit-issued identity safely.

Generic tasks:

- Treat `docs/INTEGRATOR.md` as the reusable token and browser-session contract for every integrator.
- Keep integrator-specific specs under `docs/integration/`.
- For each host system, define accepted token class, audience, tenant mapping, role source of truth, user provisioning, rollback path, and negative token tests.
- Do not add host-system-specific claims to AuthKit tokens unless claim freshness and revocation semantics are documented and tested.

### Phase 2A: Wavern Bridge Discovery

Goal: prove that Wavern can consume AuthKit-issued identity safely.

Tasks:

- Verify whether hosted Supabase can trust external RS256/JWKS tokens from AuthKit.
- If hosted Supabase cannot trust AuthKit JWKS, decide between:
  - self-hosted Supabase,
  - a PostgREST/API gateway JWT translation layer,
  - or keeping Supabase Auth only for database access while AuthKit protects Wavern API calls.
- Define Wavern claims:
  - `sub`: AuthKit user id.
  - `tenant_id`: AuthKit tenant id.
  - `empresa_id`: Wavern company id, if different from `tenant_id`.
  - `wavern_role`: Wavern role such as `super_admin`, `admin_empresa`, or user role.
  - optional `subscription_plan` if needed by Wavern authorization.
- Define user provisioning:
  - registration hook or webhook from AuthKit to Wavern,
  - idempotent creation of Wavern profile/company membership rows,
  - rollback/retry behavior when provisioning fails.
- Define migration for existing Supabase Auth users into AuthKit.

Acceptance criteria:

- A written Wavern auth integration spec exists under `docs/integration/`.
- One HML user can authenticate with AuthKit and call a protected Wavern endpoint.
- Claims are validated server-side, not trusted from the browser.
- Supabase/RLS feasibility is proven or a fallback architecture is selected.

### Phase 3: Module Registry And Presets

Goal: make cost reduction operable rather than tribal knowledge.

Tasks:

- Create `docs/MODULES.md` with module registry:
  - MFA.
  - Passkeys.
  - OAuth/OIDC provider.
  - Distributed rate limiting.
  - Email outbox.
  - RabbitMQ dispatch.
  - Async audit writer.
  - Retention scheduler.
  - CSRF.
  - CORS.
  - Origin firewall.
  - Argon2 tuning.
- Define presets:
  - `tier-00e-existing-host-sidecar`.
  - `tier-00h-cost-optimized-micro-vps`.
  - `tier-0s-solo-vps`.
  - `tier-1s-solo-vps-large`.
  - `tier-2m-managed-light`.
  - `tier-3r-resilient-direct`.
  - `tier-4f-full-production`.
  - `tier-0p-postgres-only`.
- Document what each preset may disable, what it must keep, and which production validator rule should enforce it.

Acceptance criteria:

- Public docs do not imply unsupported no-Redis production.
- Security feature switches are explicitly separated from infrastructure cost switches.
- Each preset maps to cost and user envelopes in `docs/strategy/authkit-cost-model.md`.

### Phase 4: Low-Cost Provider Expansion

Goal: reduce email vendor lock-in and operating cost.

Tasks:

- Add an SMTP or SES-backed `EmailProvider`.
- Add production validation for provider-specific required secrets.
- Keep logging provider rejected in production.
- Add tests for provider selection, timeout behavior, failure retry, and outbox state transitions.

Acceptance criteria:

- `AUTH_EMAIL_PROVIDER_TYPE=smtp` can run in production with validated credentials.
- Resend remains a supported provider.
- Direct and queue modes both work with the selected provider.

### Phase 5: Optional PostgreSQL-Only Token Storage

Goal: enable Redis-free operation where managed Redis cost or operational policy requires it.

This phase is implemented as an optional single-instance path and should be used only if an integrator or the product strategy needs Redis removal. It is not required for the cheapest standard tiers because Tier 00E, Tier 00H, and Tier 0S can all run Redis locally or on already-paid infrastructure.

Tasks:

- Add Flyway migration for JDBC token-state tables.
- Implement `JdbcTokenStorage`.
- Implement atomic refresh rotation and family reuse detection with row locks.
- Implement recovery token consume with row lock/delete.
- Implement MFA login challenge consume with row lock/delete.
- Implement bounded session pagination without unbounded reads.
- Add cleanup job for expired token-state rows.
- Update `OAuthTokenRevocationService` to support persistent JDBC revocation or document OAuth provider disabled as a Tier 0P prerequisite.
- Add production validator rules:
  - no Redis allowed only in explicit JDBC-token single-instance profile,
  - multi-replica no-Redis is rejected unless separately proven,
  - OAuth/MFA requirements are checked against the chosen token backend.
- Add PostgreSQL concurrency tests.

Acceptance criteria:

- First-party access tokens still require active server-side session state.
- Logout, logout-all, password reset, session revocation, account deletion, and refresh reuse still invalidate sessions.
- Concurrent refresh replay detection is correct.
- Recovery and MFA challenge tokens are one-time use.
- No unbounded session-list reads are introduced.

### Phase 6: Wavern HML Migration

Goal: integrate Wavern with AuthKit while preserving rollback ability.

Tasks:

- Replace Wavern login/register/recovery frontend calls with AuthKit APIs.
- Use HttpOnly refresh cookie and in-memory access token handling.
- Echo AuthKit CSRF cookie header for refresh/logout.
- Add MFA login and enrollment UI.
- Add session management UI using AuthKit paginated session endpoint.
- Move impersonation and sensitive operations to server-side step-up checks.
- Remove client-side audit as source of truth; keep it only as UX telemetry if needed.
- Build dual-auth or migration path for existing Supabase users.

Acceptance criteria:

- No AuthKit refresh token is stored in localStorage.
- Access tokens are not persisted beyond memory unless a separately audited design is approved.
- Admin and impersonation operations require server-side authorization and step-up.
- Wavern protected APIs reject missing, expired, wrong-audience, wrong-tenant, and revoked-key tokens.

### Phase 7: Post-Cost Prompt 3 Proof

Goal: prove the final selected deployment, not the old baseline.

Tasks:

- Run load and burst tests for Wavern-relevant auth flows.
- Measure p50/p95/p99, Hikari wait, Redis latency, Argon2 queueing, JVM pressure, and email backlog.
- Run chaos tests for Redis, PostgreSQL, email provider, scheduler lock contention, key rotation, and clock skew.
- Run frontend security audit.
- Prove backup/restore, key rotation, alert routing, and incident response.
- Validate JWKS refresh and revoked-key behavior in Wavern consumers.

Acceptance criteria:

- Wavern/AuthKit production readiness is reassessed with measured evidence.
- Deployment tier docs are updated with measured capacity rather than planning envelopes.
- Any accepted residual risk is documented before production cutover.

## Security Guardrails

These are non-negotiable:

- Do not disable CSRF in production.
- Do not disable CORS in production unless a gateway provides equivalent enforcement and this is documented/tested.
- Do not use localStorage for refresh tokens.
- Do not use localStorage for long-lived access tokens.
- Do not run multi-replica no-Redis deployments.
- Do not use logging email provider in production.
- Do not weaken Argon2 below production validator floors.
- Do not remove session-bound access-token validation.
- Do not disable audit logging.
- Require MFA or passkeys for Wavern administrative roles.

## Risk Register

| Risk | Severity | Mitigation |
| --- | --- | --- |
| Hosted Supabase cannot validate AuthKit JWKS | High | Prove early; choose self-hosted Supabase, gateway, or API-only AuthKit boundary |
| Tier 00E host sharing hides AuthKit resource pressure | High | Require isolated PostgreSQL/Redis, explicit resource budgets, host-level metrics, and documented shared-fate risk |
| Tier 00H low-cost provider has shared-vCPU and regional caveats | Medium | Use only for `<=100` registered users until measured; move to Tier 0S or Tier 1S when latency, compliance, or CPU pressure demands it |
| Tier 0S single instance has downtime risk | High | Use only for HML/pilot or accept a documented maintenance window; move to Tier 3R for better availability |
| Redis remains operationally required | Medium | Self-host Redis in Tier 0S/Tier 1S; implement Tier 0P only if the business case requires Redis removal |
| Frontend migration stores tokens unsafely | High | Make frontend audit part of production gate |
| Wavern RLS policies depend on `auth.uid()` semantics | High | Map claims in HML and test every tenant boundary |
| Direct email has less queue isolation than RabbitMQ | Medium | Keep durable outbox, bounded worker pool, dead-state alerts, and provider retry metrics |
| Prompt 3 deferred too long | High | Make targeted Prompt 3 proof mandatory before production cutover |

## Recommended Next Work

Start with Phase 0, Phase 1, and Phase 2 together:

- They do not require risky storage rewrites.
- They immediately reduce RabbitMQ/Kubernetes/managed-service cost.
- They answer the largest Wavern integration uncertainty: whether AuthKit JWTs can safely authorize Wavern/Supabase resources.

Defer PostgreSQL-only token storage until after Wavern HML or another concrete integration confirms that AuthKit integration is worth the extra maintenance burden.

## Phase 0-2 Artifacts

The repository artifacts for Phase 0, Phase 1, and the documentable part of Phase 2 are:

- `docs/DEPLOYMENT_TIERS.md`
- `docs/env/tier-0s-solo-vps.env.example`
- `docs/env/tier-1s-solo-vps-large.env.example`
- `docs/integration/wavern-auth-integration-spec.md`

The external HML proof from Phase 2 remains open until Wavern/Supabase are configured and a real AuthKit-issued token is used against a protected Wavern endpoint.
