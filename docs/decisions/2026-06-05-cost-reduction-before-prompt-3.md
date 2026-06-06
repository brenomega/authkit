# Decision: Cost Reduction Before Prompt 3

Date: 2026-06-05

Status: Accepted

## Decision

Proceed directly with the AuthKit cost-reduction and integrator strategy before implementing the full Prompt 3 roadmap. Wavern remains the first concrete integration target, but the deployment tiers and token boundary should stay reusable for any future system that consumes AuthKit as an authentication engine.

Prompt 3 is not mandatory before cost-reduction work. It remains mandatory, or must be replaced by an equivalent targeted proof pass, before declaring the selected Wavern/AuthKit deployment production-ready.

The practical sequence is:

1. Implement cost-reduction and deployment-tier work.
2. Integrate AuthKit with Wavern in HML/staging as an external authentication service.
3. Run a Prompt 3 subset against the actual selected deployment tier and Wavern integration before production cutover.

## Context

AuthKit is currently post-Prompt 2.5. The audit in `docs/audits/final_audit.md` rates it as conditionally production-ready for controlled small/medium production, with remaining risk primarily in operational proof: load, chaos, frontend safety, SIEM drills, backup/restore, OIDC interoperability, and release provenance.

The Wavern analysis files reviewed outside this repository were:

- `/home/breno/Documentos/Wavern/cost_reduction_strategy.md`
- `/home/breno/Documentos/Wavern/module_cost_strategy.md`
- `/home/breno/Documentos/Wavern/authkit_wavern_analysis.md`

Those documents were written shortly after Prompt 2 and before Prompt 2.5. Their high-level direction is still valid, but some implementation assumptions changed:

- Direct email dispatch already exists.
- `EmailProvider` already exists.
- RabbitMQ is already optional when `AUTH_EMAIL_OUTBOX_DISPATCH_MODE=direct`.
- Static OpenAPI, deployment modes, ShedLock, terminal outbox state, and observability artifacts already exist.
- Redis is still mandatory for safe live session storage, MFA login challenges, recovery tokens, session cursors, and first-party access-token session binding.

## Rationale

Running full Prompt 3 before cost reduction would measure the wrong architecture. Prompt 3 load, chaos, and operational drills depend on the final deployment profile: full Redis/Rabbit/Kubernetes, Redis plus direct email, or a future PostgreSQL-only token-storage mode. If we run Prompt 3 first and then remove RabbitMQ or introduce JDBC token storage, the proof would need to be repeated.

Cost-reduction work is also directly aligned with the Wavern integration objective. Wavern needs AuthKit primarily because its current auth posture is weaker: localStorage tokens, no MFA, weak password policy, client-side audit, and limited auth observability. Lowering AuthKit's deployment cost makes adoption more realistic without waiting for medium-scale production proof.

The current AuthKit code has no known critical auth blocker after Prompt 2.5. That is enough to begin HML integration and cost-tier implementation. It is not enough to claim broad production readiness for the final Wavern deployment.

## Approved Scope Before Prompt 3

The following work may proceed now:

- Maintain a dedicated cost model in `docs/strategy/authkit-cost-model.md` with explicit monthly cost ranges, registered-user ranges, DAU assumptions, price sources, and tier-selection criteria.
- Document deployment tiers and module risk/cost trade-offs.
- Use existing direct email dispatch to avoid RabbitMQ in low-cost Wavern deployments.
- Add or document low-cost profiles: existing-host sidecar when isolated host capacity already exists, cost-optimized micro VPS for up to `100` registered users, and solo-VPS baseline for up to `500` registered users.
- Add SMTP or another low-cost production email provider behind the existing `EmailProvider` SPI.
- Investigate and prototype the Wavern JWT bridge, claims, tenant mapping, and user-provisioning contract.
- Implement frontend/HML auth migration work needed to replace Supabase Auth flows with AuthKit flows.
- Optionally implement PostgreSQL-backed token storage as a separate Tier 0 feature, with explicit single-instance constraints and dedicated tests.

## Not Approved Before Prompt 3

The following claims or actions are not approved yet:

- Claiming the Wavern/AuthKit integration is production-ready at medium scale.
- Removing Redis from production without a fully tested replacement for sessions, recovery tokens, MFA login challenges, session pagination cursors, and revocation semantics.
- Disabling CSRF or CORS in production.
- Using localStorage for AuthKit access or refresh tokens in Wavern.
- Using the logging email provider in production.
- Treating local-only rate limiting as safe for multi-replica deployments.
- Treating Prompt 3 as permanently unnecessary.

## Production Gates After Cost Reduction

Before production cutover, run a targeted Prompt 3 proof pass against the selected Wavern/AuthKit deployment mode:

- Load and burst tests for login, refresh, MFA, passkey, OAuth token exchange if enabled, session-bound API reads, and session listing.
- Redis, PostgreSQL, email provider, and scheduler chaos tests for the selected tier.
- Frontend security audit covering XSS, token storage, CSRF header echo, redirects, and route protection.
- Supabase or Wavern API JWT validation proof, including JWKS refresh and revoked-key handling.
- Backup/restore and key-rotation drills.
- Alert routing for `SECURITY_ALERT`, Redis degradation, audit drops/fail-closed events, email dead messages, and Argon2 saturation.
- Release/SBOM/container-signing policy appropriate to the deployment target.

## Rejected Alternatives

### Run full Prompt 3 first

Rejected because cost-reduction work changes the measured architecture. Prompt 3 should validate the final deployment target, not the more expensive baseline that Wavern is trying to avoid.

### Integrate Wavern with the current full-cost AuthKit baseline

Rejected as the default path because it preserves the $110-255/month style infrastructure barrier identified by the cost strategy. It may still be valid for a later Tier 3 deployment.

### Skip Prompt 3 entirely

Rejected. Prompt 2.5 raised code quality and security posture, but it did not prove production latency, dependency failure behavior, frontend safety, or operational response.

## Consequences

Positive:

- Cost-reduction work can begin immediately.
- Wavern integration can start in HML without waiting for full operational proof.
- Prompt 3 measurements will be more useful because they will target the real deployment tier.

Negative:

- The project must carefully label cost-reduced tiers as constrained until measured.
- The no-Redis Tier 0 path remains non-trivial and must not be hand-waved.
- The cheapest currently supported path is a single-instance VPS tier, so availability risk must be accepted explicitly or the deployment must move to a higher tier.
- Some Wavern integration blockers, especially Supabase custom JWT/JWKS support, may invalidate the simple bridge plan and require a proxy or self-hosted Supabase path.

## Final Position

Proceed with cost reduction now. Do not implement full Prompt 3 first.

Treat Prompt 3 as the post-integration production proof phase, not as a prerequisite for starting the cost-reduction and Wavern HML integration work.
