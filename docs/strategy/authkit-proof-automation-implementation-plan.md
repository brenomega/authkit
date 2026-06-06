# AuthKit Proof, Automation, And Integration Scaffolding Implementation Plan

Date: 2026-06-06

## Purpose

This document is an implementation plan for an AI agent that will build the proof, automation, and integration scaffolding described in `docs/strategy/authkit-proof-automation-integration-scaffolding.md`.

The source-of-truth strategy explains what must exist and why. This document explains how an AI should implement it safely, in a practical order, with concrete deliverables, checks, and completion criteria.

## Read First

Before implementing anything, the AI must read:

1. `docs/strategy/authkit-proof-automation-integration-scaffolding.md`
2. `docs/strategy/authkit-cost-model.md`
3. `docs/DEPLOYMENT_TIERS.md`
4. `docs/MODULES.md`
5. `docs/INTEGRATOR.md`
6. `docs/architecture/SYSTEM_USE_CASE_FLOWS.md`
7. `docs/openapi.yaml`
8. `src/main/resources/application.yml`
9. `src/main/resources/application-test.yml`
10. Existing tests under `src/test/java/`

The AI must then inspect the current code before adding files. Do not assume an endpoint, metric, property, or test helper exists unless it is found in the repository.

## Global Rules For The AI

- Do not weaken authentication, authorization, audit, token, cookie, MFA, CSRF, CORS, password, or rate-limit protections.
- Do not add committed secrets, real tokens, real private keys, real API keys, real SMTP passwords, or production URLs.
- Do not run scripts against production by default.
- Every executable proof script must fail closed unless required environment variables are present.
- Every script that can mutate data must create unique test users and state that it is for local or HML use unless explicitly approved.
- Keep Wavern-specific assumptions in `docs/integration/wavern-auth-integration-spec.md`; keep generic integrator behavior in `docs/INTEGRATOR.md` and samples.
- Use existing AuthKit conventions, DTOs, test utilities, Maven structure, and Spring Boot idioms.
- Keep heavy load/chaos proof out of the normal Maven unit suite unless it is explicitly lightweight.
- When Docker/Testcontainers are unavailable, record that tests were skipped because Docker was unavailable. Do not treat skipped Docker proof as production proof.
- After each topic, run targeted tests and `git diff --check`.
- At the end of all topics, run the full H2 regression suite.

## Repository Layout To Create

The AI should create missing directories gradually as each topic needs them:

```text
docs/proof/
  README.md
  go-no-go-criteria.md
  performance-baselines.md
  performance-budgets.md
  reports/
  templates/
docs/runbooks/
  README.md
  deployment-targets.md
  health-readiness.md
  tier-00h-micro-vps.md
  tier-0s-solo-vps.md
  tier-1s-solo-vps.md
  tier-0p-postgres-only.md
samples/
  resource-server-spring/
  browser-session-flow/
testing/
  proof/
    chaos/
    fixtures/
    k6/
    perf/
    smoke/
deploy/
  compose/
  scripts/
  systemd/
```

Only create files that are used by the current topic. Avoid empty placeholder files unless the plan specifically asks for them.

## Recommended Execution Order

Implement in this order:

1. API/Contract Fixtures.
2. Integrator Sandbox.
3. Deployment Automation.
4. AuthKit Proof Pack.
5. Performance Tightening.

This order is intentional:

- Fixtures define what must be accepted and rejected.
- The sandbox reuses the fixtures.
- Deployment automation creates repeatable environments.
- The proof pack runs against those environments.
- Performance tightening uses proof results instead of guesses.

## Topic 1: API/Contract Fixtures

### Objective

Create deterministic token and API contract fixtures that prove AuthKit and generic integrators accept only the correct token classes, claims, issuer, audience, tenant, scope, key, and session state.

This topic should be implemented first even though it is Topic 5 in the source document.

### Why This Matters

Authentication integrations usually fail at boundaries. A host system may accidentally accept an ID token as an access token, accept an OAuth access token on a first-party AuthKit endpoint, ignore tenant claims, trust browser-provided roles, or fail to reject a revoked session.

Fixtures turn those mistakes into tests. They also give future integrators a reusable negative-test library.

### Deliverables

Create:

```text
testing/proof/fixtures/README.md
testing/proof/fixtures/tokens/*.json
testing/proof/fixtures/generate-test-tokens.sh
testing/proof/smoke/negative-contracts.sh
```

Add or update tests under:

```text
src/test/java/io/github/brenomega/authkit/
src/test/java/io/github/brenomega/authkit/infrastructure/security/
src/test/java/io/github/brenomega/authkit/service/
```

Update, if needed:

```text
docs/openapi.yaml
docs/INTEGRATOR.md
```

### Implementation Steps

#### Step 1: Inspect Existing Token Infrastructure

The AI must inspect:

- `JwtConfig`
- `JwtTokenUse`
- `JwtKeyService`
- `UserAuthoritiesFilter`
- `OAuthProviderService`
- OAuth controller routes
- Existing token tests
- Existing OpenAPI contract test

Write down:

- Which token classes currently exist.
- Which claim identifies each token class.
- Which endpoints require first-party access tokens.
- Which endpoints require OAuth access tokens.
- Which endpoints reject ID tokens.
- How first-party session binding is enforced.

Do not add fixtures until this is understood.

#### Step 2: Create Fixture Metadata

Create JSON metadata files under `testing/proof/fixtures/tokens/`.

Minimum fixtures:

```text
valid-first-party-access.json
valid-oauth-access.json
valid-id-token.json
wrong-audience.json
wrong-issuer.json
expired-token.json
missing-token-use.json
missing-tenant-id.json
tenant-mismatch.json
revoked-session.json
revoked-key-id.json
oauth-token-used-on-first-party-api.json
first-party-token-used-on-oauth-userinfo.json
id-token-used-on-api.json
```

Each file must include:

```json
{
  "name": "wrong-audience",
  "description": "OAuth access token with an audience not accepted by the sample resource API.",
  "tokenClass": "oauth_access",
  "claims": {
    "token_use": "oauth_access"
  },
  "expectedAuthKitResult": "rejected",
  "expectedIntegratorResult": "rejected",
  "expectedStatus": 401,
  "reason": "aud does not match the accepted audience"
}
```

Do not include signed JWTs in these metadata files.

#### Step 3: Add A Test Token Generator

Create `testing/proof/fixtures/generate-test-tokens.sh`.

The script must:

1. Refuse to run if the repository root cannot be found.
2. Write generated output to `target/contract-fixtures/`.
3. Use only test keys already present in the repository, or clearly documented test-only keys.
4. Refuse production key paths.
5. Print a warning that generated JWTs are test-only.
6. Never print private key material.

If shell generation is too brittle, implement a small Java test utility and make the shell script call Maven.

Acceptable output:

```text
target/contract-fixtures/tokens.json
target/contract-fixtures/valid-first-party-access.jwt
target/contract-fixtures/valid-oauth-access.jwt
```

The generated JWT files should be ignored by Git if not already ignored.

#### Step 4: Add AuthKit Negative Contract Tests

Add tests that prove:

- First-party APIs reject OAuth access tokens.
- First-party APIs reject ID tokens.
- First-party APIs reject wrong audience.
- First-party APIs reject wrong issuer.
- First-party APIs reject revoked or inactive first-party sessions.
- OAuth userinfo rejects first-party access tokens.
- OAuth userinfo rejects ID tokens.
- OAuth introspection does not mark ID tokens active.
- OAuth introspection does not mark first-party tokens active.
- OAuth revocation handles wrong token classes safely.

Prefer fast unit or slice tests if possible. Use full integration tests only where session binding or routing behavior requires it.

#### Step 5: Update OpenAPI Security Expectations

Inspect `docs/openapi.yaml`.

Ensure the spec documents:

- First-party bearer requirements for `/api/v1/users/**`.
- Admin bearer requirements for `/api/v1/admin/**`.
- OAuth access-token requirements for `/oauth2/userinfo`.
- Client authentication requirements for `/oauth2/introspect` and `/oauth2/revoke`.
- CSRF requirements for refresh/logout.
- Refresh cookie behavior.
- Session pagination response shape.
- Error responses for wrong token class.

Update the OpenAPI contract test if it does not validate security requirements.

#### Step 6: Add Negative Curl Script

Create `testing/proof/smoke/negative-contracts.sh`.

The script must:

- Require `AUTHKIT_BASE_URL`.
- Require generated fixture tokens in `target/contract-fixtures/`.
- Refuse production hostnames unless `ALLOW_PRODUCTION_PROOF=true`.
- Call endpoints with negative tokens.
- Assert expected HTTP status.
- Print a table.
- Exit nonzero on mismatch.

Do not log token values. Print fixture names only.

#### Step 7: Document Fixture Usage

Create `testing/proof/fixtures/README.md`.

Explain:

- What each fixture represents.
- Which endpoint should accept it.
- Which endpoint should reject it.
- Why token class separation matters.
- How to generate signed test tokens.
- How to run negative contract tests.

### Verification Commands

Run:

```bash
./mvnw -Dspring.profiles.active=test -Dtest='*Token*Test,*OAuth*Test,*OpenApi*Test' test
git diff --check
```

If the test selector misses relevant tests, run:

```bash
./mvnw test -Dspring.profiles.active=test
```

### Acceptance Checklist

- [x] Fixture metadata exists.
- [x] Test token generator exists and writes only to `target/`.
- [x] Generated tokens are not committed.
- [x] First-party APIs reject OAuth and ID tokens.
- [x] OAuth APIs reject first-party and ID tokens where required.
- [x] Wrong issuer/audience/token_use cases are tested.
- [x] Revoked or inactive first-party session is tested.
- [x] OpenAPI documents token class expectations.
- [x] Negative curl script exists.
- [x] Fixture README exists.
- [x] Targeted tests pass.
- [x] `git diff --check` passes.

### AI Prompt For This Topic

```text
Implement the API/Contract Fixtures topic from docs/strategy/authkit-proof-automation-implementation-plan.md.
Read the token, OAuth, OpenAPI, and security-filter code first. Create fixture metadata, a test-token generation path, AuthKit negative token tests, OpenAPI security expectation updates, a negative curl script, and fixture documentation. Do not commit generated JWTs or secrets. Run targeted token/OpenAPI tests and git diff --check.
```

## Topic 2: Integrator Sandbox

### Objective

Create a generic sample resource server and browser-session documentation that demonstrate how any host system can safely consume AuthKit.

### Why This Matters

If Wavern cannot be changed yet, AuthKit still needs a realistic integration target. The sandbox proves the integration contract without touching a real host application.

It should show:

- JWKS validation.
- Issuer validation.
- Audience validation.
- Token class validation.
- Tenant enforcement.
- Scope/role checks.
- Negative token rejection.
- Browser refresh-cookie and CSRF expectations.

### Deliverables

Create:

```text
samples/resource-server-spring/
samples/resource-server-spring/README.md
samples/browser-session-flow/README.md
```

The sample resource server should include:

```text
pom.xml
src/main/java/.../SampleResourceServerApplication.java
src/main/java/.../SecurityConfig.java
src/main/java/.../TenantController.java
src/test/java/.../TokenValidationTest.java
```

Update, if needed:

```text
docs/INTEGRATOR.md
README.md
```

### Implementation Steps

#### Step 1: Create The Sample Module

Create a standalone Maven sample under `samples/resource-server-spring/`.

The sample must not become part of AuthKit runtime. It can be a separate Maven project or a Maven module only if that does not disrupt the existing build.

Use Spring Boot resource server dependencies.

Keep the sample small:

- One application class.
- One security configuration.
- One controller.
- One test class.

#### Step 2: Configure AuthKit JWKS Validation

The sample must read:

```text
AUTHKIT_ISSUER
AUTHKIT_JWKS_URI
AUTHKIT_ACCEPTED_AUDIENCE
AUTHKIT_ACCEPTED_TOKEN_USE
```

Defaults may be local-only:

```text
http://localhost:8080
http://localhost:8080/.well-known/jwks.json
sample-resource-api
oauth_access
```

The sample must validate:

- Signature.
- Issuer.
- Audience.
- Expiration.
- `token_use`.
- `tenant_id` for tenant endpoints.
- Scope or role for protected endpoints.

#### Step 3: Add Sample Endpoints

Implement:

```text
GET /sample/me
GET /sample/tenant/{tenantId}/profile
GET /sample/admin/tenant/{tenantId}/users
```

Rules:

- `/sample/me` returns sanitized token-derived identity data.
- `/sample/tenant/{tenantId}/profile` compares path tenant to token `tenant_id`.
- `/sample/admin/tenant/{tenantId}/users` requires admin authority or configured scope.
- Never accept tenant or role from request body or arbitrary headers.

#### Step 4: Reuse Contract Fixtures

Use fixtures from `testing/proof/fixtures/`.

Tests must prove:

- Valid OAuth access token succeeds.
- ID token fails.
- First-party token fails.
- Wrong audience fails.
- Wrong issuer fails.
- Expired token fails.
- Missing tenant fails.
- Tenant mismatch fails.
- Missing scope fails.
- Admin endpoint without admin authority fails.

If signed token generation is not yet implemented, create tests using local JWT builders with test keys and keep fixture metadata as the source of expected cases.

#### Step 5: Write The Sample README

The README must explain to a developer who does not know AuthKit:

1. How to start AuthKit locally.
2. How to create or obtain an OAuth client.
3. How to get a test token.
4. How to start the sample.
5. How to call `/sample/me`.
6. How to run negative token tests.
7. How tenant validation works.
8. What the host application must still implement.

Include commands, but do not include secrets.

#### Step 6: Add Browser Session Flow Documentation

Create `samples/browser-session-flow/README.md`.

Explain:

- Login returns access token and sets refresh cookie.
- Refresh cookie is HttpOnly.
- Access token should be held in memory.
- CSRF cookie value must be echoed in the configured CSRF header for refresh/logout.
- Password reset token must be in URL fragment, not query string.
- Logout revokes session and clears cookie.
- LocalStorage is not approved for refresh tokens.

Include curl-style examples and expected headers.

#### Step 7: Keep Generic And Wavern-Specific Boundaries Separate

Update `docs/INTEGRATOR.md` with generic sandbox link and lessons.

Do not put Wavern-specific claims into the sample except as optional documentation examples. Wavern details stay in `docs/integration/wavern-auth-integration-spec.md`.

### Verification Commands

Run:

```bash
cd samples/resource-server-spring
./mvnw test
```

If the sample does not include its own wrapper, document and run:

```bash
mvn test
```

From repo root:

```bash
git diff --check
```

### Acceptance Checklist

- [x] Sample resource server exists.
- [x] Sample validates JWKS, issuer, audience, and token_use.
- [x] Sample enforces tenant path authorization.
- [x] Sample enforces scope or role.
- [x] Sample rejects wrong token classes.
- [x] Sample tests pass.
- [x] Browser session flow doc exists.
- [x] Integrator guide links to the sandbox.
- [x] Wavern-specific assumptions remain isolated.
- [x] `git diff --check` passes.

### AI Prompt For This Topic

```text
Implement the Integrator Sandbox topic from docs/strategy/authkit-proof-automation-implementation-plan.md. Build a generic Spring sample resource server under samples/resource-server-spring that validates AuthKit-style OAuth access tokens via JWKS, issuer, audience, token_use, tenant, and scope/role. Add positive and negative tests using the contract fixture cases. Add a browser-session-flow README and update generic integrator docs. Keep Wavern-specific details out of the sample. Run sample tests and git diff --check.
```

## Topic 3: Deployment Automation

### Objective

Create repeatable local/VPS deployment automation and runbooks for Redis-backed and JDBC-token AuthKit tiers.

### Why This Matters

Cost-reduced deployments are operationally sensitive. A small mistake can expose Redis, run AuthKit with default secrets, disable CSRF, accidentally select logging email in production, or deploy JDBC token storage with multiple replicas.

Automation makes safe deployment repeatable and reviewable.

### Deliverables

Create:

```text
deploy/compose/docker-compose.redis-direct.yml
deploy/compose/docker-compose.jdbc-direct.yml
deploy/compose/docker-compose.queue.yml
deploy/compose/.env.redis-direct.example
deploy/compose/.env.jdbc-direct.example
deploy/systemd/authkit.service.example
deploy/systemd/authkit.env.example
deploy/systemd/authkit-backup.service.example
deploy/systemd/authkit-backup.timer.example
deploy/systemd/authkit-restore-check.service.example
deploy/scripts/backup-postgres.sh
deploy/scripts/restore-postgres-check.sh
deploy/scripts/backup-redis.sh
deploy/scripts/collect-diagnostics.sh
deploy/scripts/preflight-config.sh
docs/runbooks/README.md
docs/runbooks/deployment-targets.md
docs/runbooks/health-readiness.md
docs/runbooks/tier-00h-micro-vps.md
docs/runbooks/tier-0s-solo-vps.md
docs/runbooks/tier-1s-solo-vps.md
docs/runbooks/tier-0p-postgres-only.md
```

### Implementation Steps

#### Step 1: Inspect Existing Deployment Files

Read:

- `DEPLOYMENT.md`
- `docs/DEPLOYMENT_MODES.md`
- `docs/DEPLOYMENT_TIERS.md`
- `docs/env/*.env.example`
- Kubernetes manifests under `k8s/`, if present.
- `application.yml`
- `ProductionConfigValidator`

List required environment variables and tier-specific differences.

#### Step 2: Add Compose Files

Implement `docker-compose.redis-direct.yml`:

- AuthKit service.
- PostgreSQL service.
- Redis service.
- Optional Mailpit or local SMTP service.
- Direct email mode.
- Redis token backend.

Implement `docker-compose.jdbc-direct.yml`:

- AuthKit service.
- PostgreSQL service.
- Optional Mailpit or local SMTP service.
- No Redis.
- JDBC token backend.
- `AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE=true`.

Implement `docker-compose.queue.yml` only if existing RabbitMQ queue mode can be represented safely.

Rules:

- Use example secrets only in `.env.example`, not real secrets.
- Use `CHANGE-ME` for values that must be replaced.
- Bind PostgreSQL and Redis to internal networks only.
- Do not expose PostgreSQL or Redis ports unless the file is explicitly local-dev and says so.
- Include health checks where practical.

#### Step 3: Add Compose Env Examples

Create `.env.redis-direct.example` and `.env.jdbc-direct.example`.

They must include:

- DB settings.
- Redis settings for Redis mode.
- Token backend settings.
- Email settings.
- JWT key paths.
- CORS and CSRF settings.
- Argon2 settings.
- Audit and MFA secrets as `CHANGE-ME`.

The JDBC example must clearly say:

```text
AUTH_TOKEN_STORAGE_BACKEND=jdbc
AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE=true
```

The Redis example must clearly say:

```text
AUTH_TOKEN_STORAGE_BACKEND=redis
AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE=false
```

#### Step 4: Add Systemd Examples

Create systemd example files.

`authkit.service.example` must include safe hardening options where compatible:

- Dedicated user.
- `NoNewPrivileges=true`.
- `PrivateTmp=true`.
- Restricted write paths.
- Environment file.
- Restart policy.

Do not make impossible promises. If a hardening option may break file-based keys or logs, document required paths.

#### Step 5: Add Backup Scripts

Implement scripts with defensive shell settings:

```bash
set -euo pipefail
```

Scripts must:

- Refuse missing required variables.
- Refuse empty backup directories.
- Never print passwords.
- Write checksums.
- Print clear next steps.

`backup-postgres.sh` should use `pg_dump`.

`restore-postgres-check.sh` should restore into a temporary database and run simple checks.

`backup-redis.sh` should be Redis-mode only and must refuse empty Redis password.

`collect-diagnostics.sh` should collect:

- Git commit, if available.
- Java version.
- AuthKit environment summary with secrets masked.
- Health endpoint response.
- Prometheus snapshot.
- Recent logs if path is configured.

#### Step 6: Add Preflight Config Script

`preflight-config.sh` must validate environment before startup.

Check:

- Required DB env vars.
- Redis backend has Redis host and password.
- JDBC backend has single-instance mode.
- Logging provider is not selected.
- SMTP has TLS/SSL and credentials when auth is enabled.
- Resend has API key when selected.
- CORS origins are not `*`.
- CSRF is enabled.
- Refresh cookie is secure.
- Argon2 floors are respected.
- Scheduler lock settings are safe.

The script should print `PASS` or `FAIL` lines and exit nonzero on failure.

#### Step 7: Add Runbooks

Each runbook must explain:

1. Who should use this tier.
2. Who should not use this tier.
3. Required host size.
4. Firewall setup.
5. Environment setup.
6. Startup.
7. Smoke testing.
8. Backup setup.
9. Restore drill.
10. Metrics check.
11. Rollback.
12. No-go conditions.

State obvious rules:

- Do not expose PostgreSQL.
- Do not expose Redis.
- Do not use `CHANGE-ME`.
- Do not use logging email provider in production.
- Do not disable CSRF.
- Do not run Tier 0P with multiple AuthKit instances.

### Verification Commands

Run:

```bash
bash -n deploy/scripts/*.sh
git diff --check
```

If Docker is available:

```bash
docker compose -f deploy/compose/docker-compose.redis-direct.yml config
docker compose -f deploy/compose/docker-compose.jdbc-direct.yml config
```

If shellcheck is available:

```bash
shellcheck deploy/scripts/*.sh
```

### Acceptance Checklist

- [x] Redis-direct compose exists.
- [x] JDBC-direct compose exists.
- [x] Queue compose exists or is explicitly deferred with rationale.
- [x] Env examples contain no real secrets.
- [x] Systemd examples exist.
- [x] Backup scripts exist and pass `bash -n`.
- [x] Preflight script exists and pass/fail logic is documented.
- [x] Runbooks exist for Tier 00H, 0S, 1S, and 0P.
- [x] Health/readiness runbook exists.
- [x] `git diff --check` passes.

### AI Prompt For This Topic

```text
Implement the Deployment Automation topic from docs/strategy/authkit-proof-automation-implementation-plan.md. Create compose stacks, env examples, systemd examples, backup/restore/diagnostic/preflight scripts, and tier runbooks. Keep scripts safe by default, no secrets, no production mutation, and explicit Redis vs JDBC backend settings. Run bash -n, compose config if Docker is available, shellcheck if available, and git diff --check.
```

## Topic 4: AuthKit Proof Pack

### Objective

Create executable smoke, load, chaos, metrics, and reporting tools that prove AuthKit behavior for selected tiers.

This topic should be implemented after Deployment Automation because proof scripts need repeatable environments.

### Why This Matters

The proof pack moves AuthKit from "implemented" to "evidence-backed." It shows whether low-cost tiers actually behave correctly under expected load and dependency failures.

### Deliverables

Create:

```text
docs/proof/README.md
docs/proof/templates/proof-report-template.md
docs/proof/go-no-go-criteria.md
testing/proof/run-proof.sh
testing/proof/smoke/register-confirm-login-refresh-logout.sh
testing/proof/smoke/password-recovery-reset.sh
testing/proof/smoke/mfa-login.sh
testing/proof/smoke/session-list-revoke.sh
testing/proof/smoke/oauth-code-token-userinfo.sh
testing/proof/smoke/health-and-metrics.sh
testing/proof/smoke/collect-prometheus-snapshot.sh
testing/proof/k6/login-refresh.js
testing/proof/k6/registration-recovery.js
testing/proof/k6/mfa-login.js
testing/proof/k6/session-pagination.js
testing/proof/k6/oauth-token-introspection.js
testing/proof/k6/mixed-auth-workload.js
testing/proof/chaos/redis-stop-during-login.sh
testing/proof/chaos/redis-stop-during-refresh.sh
testing/proof/chaos/postgres-restart-during-outbox.sh
testing/proof/chaos/smtp-fail-during-recovery.sh
testing/proof/chaos/scheduler-lock-contention.sh
testing/proof/chaos/jdbc-token-concurrent-refresh.sh
```

### Implementation Steps

#### Step 1: Create Proof Matrix

Create `docs/proof/README.md`.

Include matrix rows for:

- Tier 00H Redis direct.
- Tier 0S Redis direct.
- Tier 1S Redis direct.
- Tier 0P JDBC direct.

Use user and DAU ranges from `docs/strategy/authkit-cost-model.md`.

Do not invent new sizing claims.

#### Step 2: Create Report Template

Create `docs/proof/templates/proof-report-template.md`.

Include all fields from the source-of-truth document:

- Commit.
- Branch.
- Tier.
- Backend.
- Host.
- JVM.
- DB.
- Redis, if used.
- Email.
- Commands.
- Latency.
- Throughput.
- Errors.
- Metrics.
- Incidents.
- Go/no-go.

Add a warning that secrets and raw tokens must not be pasted.

#### Step 3: Implement Smoke Scripts

Each smoke script must:

- Use `set -euo pipefail`.
- Require `AUTHKIT_BASE_URL`.
- Refuse production-looking hosts unless `ALLOW_PRODUCTION_PROOF=true`.
- Mask sensitive output.
- Use unique test users.
- Assert expected HTTP statuses.
- Exit nonzero on failure.

Use a shared helper file if useful:

```text
testing/proof/smoke/lib.sh
```

The helper can provide:

- `require_env`
- `refuse_production`
- `mask_email`
- `assert_status`
- `json_value`
- `unique_email`

Keep dependencies simple. If `jq` is required, check for it and print a clear error.

#### Step 4: Implement k6 Load Scripts

Each k6 script must:

- Read `AUTHKIT_BASE_URL`.
- Read scenario size from env.
- Generate unique users.
- Define thresholds.
- Avoid printing tokens.
- Include tags for endpoint and flow.

Add a `testing/proof/k6/README.md` explaining how to install and run k6.

#### Step 5: Implement Metrics Snapshot Script

`collect-prometheus-snapshot.sh` must:

- Save before and after snapshots.
- Extract important metrics.
- Write to a report directory.
- Refuse missing `AUTHKIT_BASE_URL`.

Do not require Prometheus server. Use AuthKit `/actuator/prometheus`.

#### Step 6: Implement Chaos Scripts

Chaos scripts must be safe:

- Local/HML only by default.
- Require explicit flags.
- Refuse production by default.
- Document expected behavior at the top of each file.
- Print exact services they will stop/restart.

If a script depends on Docker Compose, require `COMPOSE_FILE` and check that Docker is available.

#### Step 7: Implement Proof Runner

`testing/proof/run-proof.sh` should:

1. Parse `--tier`, `--backend`, `--email-provider`, `--load`, and `--chaos`.
2. Print Git commit and dirty status.
3. Create report directory under `docs/proof/reports/`.
4. Run smoke scripts.
5. Run k6 scripts when requested.
6. Run chaos scripts only when `--chaos true`.
7. Collect metrics before and after.
8. Print report template path.

#### Step 8: Add CI Guardrails

If CI files exist, add lightweight jobs only:

- Shell syntax.
- k6 script syntax, if available.
- Fixture metadata validation.

Do not run heavy load/chaos on every PR.

### Verification Commands

Run:

```bash
bash -n testing/proof/**/*.sh
git diff --check
```

If globstar is not enabled:

```bash
find testing/proof -name '*.sh' -print -exec bash -n {} \;
```

If k6 is available:

```bash
k6 inspect testing/proof/k6/login-refresh.js
k6 inspect testing/proof/k6/mixed-auth-workload.js
```

### Acceptance Checklist

- [x] Proof matrix exists.
- [x] Report template exists.
- [x] Go/no-go criteria exists.
- [x] Smoke scripts exist and are syntax-valid.
- [x] k6 scripts exist.
- [x] Metrics snapshot script exists.
- [x] Chaos scripts exist and refuse production by default.
- [x] Proof runner exists.
- [x] Scripts do not print secrets or raw tokens.
- [x] `git diff --check` passes.

### AI Prompt For This Topic

```text
Implement the AuthKit Proof Pack topic from docs/strategy/authkit-proof-automation-implementation-plan.md. Create proof docs, report templates, safe smoke scripts, k6 load scripts, metrics snapshot collection, chaos scripts, a proof runner, and go/no-go criteria. Scripts must refuse production by default, never print tokens/secrets, and use environment variables. Run shell syntax checks, k6 inspect if available, and git diff --check.
```

## Topic 5: Performance Tightening

### Objective

Create evidence-based performance measurement and tuning scaffolding for AuthKit's critical paths.

### Why This Matters

Low-cost tiers are constrained by CPU, memory, database connections, direct email workers, and token backend latency. Performance tuning must be based on measurement, not guesses, and it must never reduce security controls below production floors.

### Deliverables

Create:

```text
docs/proof/performance-baselines.md
docs/proof/performance-budgets.md
testing/proof/perf/README.md
testing/proof/perf/sql/session-pagination-explain.sql
testing/proof/perf/sql/refresh-rotation-explain.sql
testing/proof/perf/sql/recovery-consume-explain.sql
testing/proof/perf/sql/mfa-challenge-consume-explain.sql
testing/proof/perf/sql/outbox-claim-explain.sql
testing/proof/perf/sql/audit-insert-explain.sql
```

Add tests or benchmarks for:

- Argon2 encode/verify.
- Redis token storage, if Docker is available.
- JDBC token storage.
- Session pagination.
- Email outbox transitions.
- Synchronous audit writes.
- OAuth token issue/introspection.

### Implementation Steps

#### Step 1: Create Baseline Document

Create `docs/proof/performance-baselines.md`.

For each tier, include:

- Host size.
- JVM heap.
- Hikari max.
- Token backend.
- Email mode.
- Expected bottleneck.
- Current status: `estimated`, `measured`, `operator-provided`, or `unknown`.

Do not present estimates as measured values.

#### Step 2: Create Performance Budget Document

Create `docs/proof/performance-budgets.md`.

For each tier, define:

- Login p95 budget.
- Refresh p95 budget.
- Session list p95 budget.
- OAuth introspection p95 budget.
- Maximum outbox backlog age.
- Maximum Hikari pending wait.
- Maximum allowed critical audit drops: zero.

Mark budgets as provisional until measured.

#### Step 3: Add Lightweight Benchmarks Or Performance Tests

Prefer tests that can run locally with H2 for approximate behavior and Testcontainers for PostgreSQL/Redis when available.

Suggested test classes:

```text
src/test/java/io/github/brenomega/authkit/performance/Argon2PerformanceTest.java
src/test/java/io/github/brenomega/authkit/performance/JdbcTokenStoragePerformanceTest.java
src/test/java/io/github/brenomega/authkit/performance/EmailOutboxPerformanceTest.java
src/test/java/io/github/brenomega/authkit/performance/OAuthTokenPerformanceTest.java
```

Do not run slow tests by default unless they are explicitly lightweight. Consider JUnit tags:

```text
@Tag("performance")
```

Document how to run:

```bash
./mvnw -Dgroups=performance test
```

or another working Maven selector.

#### Step 4: Add PostgreSQL Query Plan SQL

Create SQL files under `testing/proof/perf/sql/`.

Each file must include:

- Purpose.
- Required setup.
- Query under test.
- Expected index.
- `EXPLAIN (ANALYZE, BUFFERS)` command.

Queries to cover:

- JDBC session keyset pagination.
- Refresh rotation family/session lock.
- Recovery token consume.
- MFA challenge consume.
- Outbox claim query.
- Security event insert or lookup.

#### Step 5: Add Tuning Procedure Documentation

In `testing/proof/perf/README.md`, document:

- How to run benchmarks.
- How to read results.
- How to tune Hikari.
- How to tune Argon2 concurrency.
- How to tune direct email workers.
- How to compare Redis vs JDBC token storage.
- How to avoid unsafe tuning.

State explicitly:

- Do not lower Argon2 floors.
- Do not increase Hikari until evidence shows it helps.
- Do not increase direct email workers beyond provider/host capacity.
- Do not use H2 timings as PostgreSQL production proof.

#### Step 6: Update Tier Env Docs Only With Evidence

If performance results justify config changes, update:

- `docs/env/tier-0s-solo-vps.env.example`
- `docs/env/tier-1s-solo-vps-large.env.example`
- `docs/DEPLOYMENT_TIERS.md`
- `docs/strategy/authkit-cost-model.md`

Each update must cite the measured report or state it is still a baseline.

### Verification Commands

Run:

```bash
./mvnw -Dspring.profiles.active=test -Dtest='*PerformanceTest,*JdbcTokenStorageTest,*EmailOutbox*Test,*OAuth*Test' test
git diff --check
```

If tagged tests are used, run the documented Maven command and verify it actually selects those tests.

### Acceptance Checklist

- [x] Performance baseline doc exists.
- [x] Performance budget doc exists.
- [x] SQL query plan files exist.
- [x] Performance README exists.
- [x] Lightweight performance tests or benchmarks exist.
- [x] Slow tests are tagged or isolated.
- [x] Hikari tuning procedure is documented.
- [x] Argon2 tuning procedure is documented.
- [x] Direct email tuning procedure is documented.
- [x] Redis/JDBC comparison procedure is documented.
- [x] No security floors are lowered.
- [x] Targeted tests pass.
- [x] `git diff --check` passes.

### AI Prompt For This Topic

```text
Implement the Performance Tightening topic from docs/strategy/authkit-proof-automation-implementation-plan.md. Create performance baseline and budget docs, PostgreSQL EXPLAIN SQL files, a performance README, and lightweight/tagged benchmarks for Argon2, JDBC token storage, email outbox, audit, and OAuth paths where practical. Do not lower security settings. Update tier defaults only with measured evidence. Run targeted tests and git diff --check.
```

## Final Verification For The Whole Workstream

After all topics are implemented, run:

```bash
git diff --check
./mvnw test -Dspring.profiles.active=test
```

If Docker is available:

```bash
./mvnw -Dspring.profiles.active=test -Dtest=PostgresMigrationTest test
```

If Docker is not available, record:

```text
PostgresMigrationTest skipped because Docker/Testcontainers was unavailable.
```

Also run any implemented script syntax checks:

```bash
find testing deploy -name '*.sh' -print -exec bash -n {} \;
```

If k6 is available:

```bash
find testing/proof/k6 -name '*.js' -print -exec k6 inspect {} \;
```

## Final Workstream Acceptance Checklist

- [x] API/Contract Fixtures are implemented.
- [x] Integrator Sandbox is implemented.
- [x] Deployment Automation is implemented.
- [x] AuthKit Proof Pack is implemented.
- [x] Performance Tightening scaffolding is implemented.
- [x] README links all major new docs.
- [x] No committed secrets exist.
- [x] No generated JWTs are committed unless clearly test-only and approved.
- [x] No production-host scripts run by default.
- [x] All executable scripts have syntax checks.
- [x] Targeted tests pass.
- [x] Full H2 suite passes.
- [x] Docker-backed tests pass or are explicitly skipped because Docker is unavailable.
- [x] Remaining unproven items are listed in a proof report or follow-up issue.

## Suggested Branch And Commit Naming

Use a specific branch name:

```text
authkit-proof-automation-scaffolding
```

Use a specific commit message:

```text
Add AuthKit proof and integration scaffolding
```

If implementing topic by topic, use smaller commits:

```text
Add token contract fixtures
Add generic resource server sandbox
Add tier deployment automation
Add AuthKit proof runner scripts
Add performance proof scaffolding
```

Do not use generic messages such as `prompt implementation` or `update docs`.
