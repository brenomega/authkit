# AuthKit Proof, Automation, And Integration Scaffolding Plan

Date: 2026-06-06

## Purpose

This document is the source of truth for the next AuthKit-only workstream when the host application, such as Wavern, cannot be changed yet.

The objective is not to add more authentication features. The objective is to build proof, automation, and integration scaffolding around the features already implemented so AuthKit becomes easier to operate, easier to validate, easier to integrate, and easier to trust.

This work covers five topics:

1. AuthKit Proof Pack.
2. Integrator Sandbox.
3. Deployment Automation.
4. Performance Tightening.
5. API/Contract Fixtures.

## Scope

In scope:

- AuthKit repository changes only.
- Test tooling, proof scripts, sample applications, deployment scripts, runbooks, fixtures, reports, and documentation.
- Evidence for Redis-backed tiers and explicit single-instance JDBC-token tiers.
- Evidence for direct email mode, SMTP, Resend, OAuth/OIDC, first-party session binding, MFA, passkeys, recovery, audit, and scheduler behavior.

Out of scope:

- Wavern frontend changes.
- Wavern backend changes.
- Supabase schema/RLS migration.
- Production cutover.
- New authentication features that are not required to prove existing behavior.
- Relaxing security controls to reduce cost.

## Guiding Principles

- Prefer measured evidence over assumptions.
- Treat missing proof as a production risk.
- Keep all proof artifacts reproducible from the repository.
- Make every script safe by default: no committed secrets, no destructive default targets, no production URLs.
- Keep low-cost tiers honest: cheaper operation is allowed, weaker authentication is not.
- Keep integrator-specific assumptions outside generic AuthKit contracts.
- Use the same token classes, cookies, CSRF rules, and session binding that real integrators must use.
- Every generated report must state the exact commit, configuration, tier, and test command used.

## Common Directory Layout

Create this structure as the first step before implementing any individual topic:

```text
docs/proof/
  README.md
  reports/
  templates/
docs/runbooks/
  README.md
samples/
  resource-server-spring/
testing/
  proof/
    k6/
    smoke/
    chaos/
    fixtures/
deploy/
  compose/
  systemd/
  scripts/
```

Recommended ownership:

- `docs/proof/`: proof plan, report templates, completed local/HML reports.
- `docs/runbooks/`: operator procedures.
- `samples/`: integrator examples that compile and run.
- `testing/proof/`: executable proof scripts.
- `deploy/`: local, VPS, and tier automation.

Do not place secrets in these directories. Use `.env.example` files only.

## Topic 1: AuthKit Proof Pack

### Why This Is Important

AuthKit has many security-sensitive flows that must behave correctly under normal load, hostile traffic, dependency degradation, and tier-specific constraints. A green unit test suite proves individual code paths, but it does not prove that a selected deployment tier can run real authentication traffic safely.

The Proof Pack gives AuthKit a repeatable way to answer these questions:

- Can Tier 00H, Tier 0S, Tier 1S, or Tier 0P handle the expected login and refresh volume?
- Does Argon2 become saturated before the database or Redis/JDBC token backend?
- Does direct email mode accumulate backlog under registration or recovery bursts?
- Does session revocation actually invalidate first-party access tokens quickly?
- Does refresh-token replay detection still revoke the token family?
- Does Redis loss behave differently in Redis mode vs JDBC mode?
- Does JDBC token storage remain one-time and bounded under concurrent attempts?
- Do audit and scheduler metrics expose security-relevant failures?
- Is the selected tier acceptable for HML, pilot production, or full production?

Without this proof, production readiness remains speculative. This is especially important because the cost-reduction tiers intentionally use smaller infrastructure.

### Implementation Process

#### Step 1: Define The Proof Matrix

Create `docs/proof/README.md`.

Document every proof target as a row:

```text
Tier | Backend | Email mode | Email provider | Expected users | DAU | Objective | Required scripts | Required report
```

Minimum rows:

- Tier 00H, Redis token backend, direct email, SMTP or Resend.
- Tier 0S, Redis token backend, direct email, SMTP or Resend.
- Tier 1S, Redis token backend, direct email, SMTP or Resend.
- Tier 0P, JDBC token backend, direct email, SMTP or Resend, single instance only.

For each row, state:

- User envelope.
- Daily active user assumption.
- Login rate.
- Refresh rate.
- Email rate.
- Expected active sessions.
- Whether the proof is local-only, HML, or production-like.

Do not invent new tier sizes. Reuse `docs/strategy/authkit-cost-model.md`.

#### Step 2: Create A Report Template

Create `docs/proof/templates/proof-report-template.md`.

The template must include:

```text
Title
Date
Commit SHA
Branch
AuthKit version
Tier
Token backend
Email mode
Email provider
JVM settings
Database settings
Redis settings, if used
SMTP/Resend settings, without secrets
Host CPU/RAM
Test data volume
Commands executed
Results summary
Latency table
Throughput table
Error table
Metrics table
Security behavior table
Incidents during test
Go/no-go recommendation
Known limitations
```

The report must never include:

- Raw passwords.
- Refresh tokens.
- Access tokens.
- MFA secrets.
- SMTP passwords.
- Resend API keys.
- Private keys.

#### Step 3: Add Smoke Tests

Create `testing/proof/smoke/`.

Add shell scripts that use `curl` or a small Java/Node/Python CLI. Keep them deterministic and easy to run.

Minimum smoke scripts:

- `register-confirm-login-refresh-logout.sh`
- `password-recovery-reset.sh`
- `mfa-login.sh`
- `session-list-revoke.sh`
- `oauth-code-token-userinfo.sh`
- `health-and-metrics.sh`

Each script must:

1. Read configuration from environment variables.
2. Refuse to run if `AUTHKIT_BASE_URL` is empty.
3. Refuse to run against a hostname that looks production unless `ALLOW_PRODUCTION_PROOF=true`.
4. Create its own test user with a unique email.
5. Print only masked email addresses and IDs.
6. Fail with nonzero exit code if any required HTTP status is wrong.
7. Delete or revoke its test sessions when possible.

Expected environment variables:

```text
AUTHKIT_BASE_URL
AUTHKIT_TEST_EMAIL_DOMAIN
AUTHKIT_TEST_PASSWORD
AUTHKIT_ADMIN_ACCESS_TOKEN
AUTHKIT_OAUTH_CLIENT_ID
AUTHKIT_OAUTH_CLIENT_SECRET
ALLOW_PRODUCTION_PROOF
```

If email confirmation requires reading the outbox directly, document that this is local/HML-only and must not be used against production data.

#### Step 4: Add Load Scripts

Create `testing/proof/k6/`.

Use k6 for load scripts because it is lightweight, common, and easy to run locally or in CI-like environments.

Minimum scripts:

- `login-refresh.js`
- `registration-recovery.js`
- `mfa-login.js`
- `session-pagination.js`
- `oauth-token-introspection.js`
- `mixed-auth-workload.js`

Each script must:

1. Read `AUTHKIT_BASE_URL`.
2. Read scenario size from environment variables.
3. Avoid hardcoded secrets.
4. Generate unique user identities.
5. Capture HTTP status distribution.
6. Capture p50, p95, and p99 latency.
7. Fail thresholds when error rates exceed the configured bound.

Recommended baseline thresholds for HML proof:

```text
http_req_failed < 1%
p95 login < 1500 ms for test Argon2 settings
p95 refresh < 300 ms
p95 session list < 300 ms
p95 OAuth introspection < 300 ms
no 5xx during steady state
```

For production Argon2 settings, do not use the HML login threshold blindly. Measure and document realistic values.

#### Step 5: Add Metrics Collection

Create `testing/proof/smoke/collect-prometheus-snapshot.sh`.

The script must:

1. Call `/actuator/prometheus`.
2. Save output to `docs/proof/reports/<date>-<tier>/prometheus-before.txt`.
3. Run the proof workload.
4. Save output to `prometheus-after.txt`.
5. Extract key metrics into `metrics-summary.txt`.

Track at least:

- HTTP request count and latency.
- JVM heap and GC.
- Hikari active, idle, pending, timeout.
- Argon2 saturation.
- Redis degradation metrics.
- JDBC token cleanup metrics.
- Audit dropped/fail-closed metrics.
- Email outbox retry/dead metrics.
- Scheduler failure metrics.
- Refresh-token reuse metrics.
- Abuse fail-closed metrics.

If a metric does not exist, record that as a gap and decide whether to add it.

#### Step 6: Add Chaos Scripts

Create `testing/proof/chaos/`.

Minimum scripts:

- `redis-stop-during-login.sh`
- `redis-stop-during-refresh.sh`
- `postgres-restart-during-outbox.sh`
- `smtp-fail-during-recovery.sh`
- `resend-timeout-simulation.sh`
- `scheduler-lock-contention.sh`
- `jdbc-token-concurrent-refresh.sh`

Each script must:

1. State which tier it applies to.
2. State whether it is safe for local only or HML.
3. Refuse production by default.
4. Record expected behavior before running.
5. Run the failure.
6. Run a verification command after the failure.
7. Write a short result file.

Example expected behavior:

- Redis token backend plus Redis outage: high-risk endpoints either degrade according to config or fail closed if enabled.
- JDBC token backend plus no Redis: login/refresh/session state remains available, but distributed abuse controls are local only.
- SMTP outage: outbox retries and eventually reaches `DEAD`; user operation does not expose provider details.
- Scheduler contention: only one worker processes a job under the ShedLock window.

#### Step 7: Define Go/No-Go Criteria

Create `docs/proof/go-no-go-criteria.md`.

Minimum no-go criteria:

- Any authentication bypass.
- Any token class confusion.
- Refresh replay does not revoke the family.
- Logout-all or password reset does not revoke sessions.
- Recovery token can be consumed more than once.
- MFA challenge can be consumed more than once.
- Email outbox loses messages silently.
- Critical audit failure does not fail closed.
- Hikari pending threads grow continuously under expected load.
- Argon2 saturation causes uncontrolled request pileup.
- JDBC mode is used with more than one app instance.
- Redis mode runs without Redis authentication in production.
- Any committed secret appears in proof artifacts.

#### Step 8: Add A Proof Runner

Create `testing/proof/run-proof.sh`.

The runner must:

1. Print the current Git commit.
2. Print dirty-worktree status.
3. Require a tier name.
4. Require a backend name.
5. Run smoke tests first.
6. Run load tests second.
7. Run chaos tests only when explicitly requested.
8. Collect metrics before and after.
9. Create a report directory.
10. Print the next report file to complete.

Example:

```bash
testing/proof/run-proof.sh \
  --tier tier-0s-solo-vps \
  --backend redis \
  --email-provider smtp \
  --load hml \
  --chaos false
```

#### Step 9: Add CI Guardrails

Do not run heavy load tests on every pull request.

Add lightweight CI jobs for:

- Smoke script syntax.
- k6 script syntax, if k6 is available.
- Test fixture validation.
- Report template existence.

Keep full proof runs manual or scheduled because they need real services and meaningful time.

#### Step 10: Acceptance Criteria

This topic is complete when:

- Proof matrix exists.
- Report template exists.
- Smoke scripts exist.
- Load scripts exist.
- Chaos scripts exist.
- Metrics snapshot collection exists.
- Go/no-go criteria exist.
- A proof runner exists.
- At least one Tier 0S Redis proof report exists.
- At least one Tier 0P JDBC proof report exists if Tier 0P remains a supported option.

## Topic 2: Integrator Sandbox

### Why This Is Important

AuthKit is intended to integrate with host systems as an authentication engine. If the host cannot be changed yet, AuthKit still needs a safe place to prove what an integrator must do.

The Integrator Sandbox prevents future integration mistakes by showing a working example of:

- JWKS discovery.
- JWT issuer validation.
- Audience validation.
- Token class separation.
- Tenant claim validation.
- Role mapping.
- OAuth access token use.
- Rejection of first-party tokens where OAuth tokens are required.
- Rejection of OAuth tokens where first-party tokens are required.
- CSRF and refresh-cookie handling expectations.

This is valuable for Wavern, but it must remain generic. Wavern-specific details stay in `docs/integration/wavern-auth-integration-spec.md`.

### Implementation Process

#### Step 1: Choose The Sample Shape

Create `samples/resource-server-spring/`.

Use Spring Boot because AuthKit already uses Spring and the repository already has Maven. The sample should be small, boring, and explicit.

Minimum structure:

```text
samples/resource-server-spring/
  README.md
  pom.xml
  src/main/java/.../SampleResourceServerApplication.java
  src/main/java/.../SecurityConfig.java
  src/main/java/.../TenantController.java
  src/test/java/.../TokenValidationTest.java
```

The sample is not a production app. It is an executable contract example.

#### Step 2: Define Sample Endpoints

Add endpoints:

```text
GET /sample/me
GET /sample/tenant/{tenantId}/profile
GET /sample/admin/tenant/{tenantId}/users
```

Behavior:

- `/sample/me` returns subject, tenant, scopes, and roles from the validated token.
- `/sample/tenant/{tenantId}/profile` succeeds only when token `tenant_id` matches the path.
- `/sample/admin/tenant/{tenantId}/users` requires an admin role or configured authority.

Do not trust tenant or role values sent in request bodies or headers. They must come from the token or server-side mapping.

#### Step 3: Configure JWKS Validation

In the sample `application.yml`, require:

```yaml
authkit:
  issuer: http://localhost:8080
  jwks-uri: http://localhost:8080/.well-known/jwks.json
  accepted-audience: sample-resource-api
  accepted-token-use: oauth_access
```

The sample must validate:

- Signature.
- Issuer.
- Audience.
- Expiration.
- `token_use`.
- `tenant_id`.
- Required scopes or roles.

The sample must not accept:

- Missing `token_use`.
- `id_token`.
- `first_party_access` for resource API endpoints unless the sample explicitly documents a first-party mode.
- Wrong audience.
- Wrong issuer.
- Expired token.
- Missing tenant.

#### Step 4: Add Token Validation Tests

Create tests that generate or load fixture tokens.

Tests must cover:

- Valid OAuth access token succeeds.
- ID token fails.
- First-party token fails for OAuth resource endpoint.
- Wrong audience fails.
- Wrong issuer fails.
- Expired token fails.
- Missing `tenant_id` fails when endpoint requires tenant.
- Tenant mismatch fails.
- Missing scope fails.
- Admin endpoint without admin authority fails.

If generating signed tokens is too complex in the sample, use AuthKit's test key pair and document that the keys are test-only.

#### Step 5: Document Integrator Responsibilities

In `samples/resource-server-spring/README.md`, explain:

1. Start AuthKit.
2. Register or seed a user.
3. Create an OAuth client.
4. Obtain an OAuth access token.
5. Start the sample resource server.
6. Call `/sample/me`.
7. Try a negative token case.

Also explain what the host system must own:

- User provisioning.
- Tenant mapping.
- Role mapping.
- Authorization policy.
- Audit correlation.
- Logout/session behavior for its own APIs.
- JWKS refresh and key rollover handling.

#### Step 6: Add A Browser Session Example

Create `samples/browser-session-flow/README.md`.

Do not build a full frontend unless needed. The document should show:

- Login request.
- Refresh cookie is HttpOnly.
- CSRF cookie must be echoed as a header for refresh/logout.
- Access token should be kept in memory.
- Reset tokens belong in URL fragments, not query strings.
- Logout clears refresh cookie and revokes session.

Include curl examples where possible.

#### Step 7: Keep Generic And Wavern-Specific Docs Separate

Update `docs/INTEGRATOR.md` with generic lessons only.

Update `docs/integration/wavern-auth-integration-spec.md` only for Wavern-specific mapping such as:

- `empresa_id`.
- `wavern_role`.
- Supabase/RLS feasibility.
- Wavern profile provisioning.

Do not put Wavern claims into generic sample code unless clearly marked as an example.

#### Step 8: Acceptance Criteria

This topic is complete when:

- A sample resource server exists.
- It validates AuthKit JWKS.
- It rejects wrong token classes.
- It enforces tenant path/object authorization.
- It includes positive and negative tests.
- It has a README with run commands.
- Generic integrator docs are updated.
- Wavern-specific assumptions remain isolated.

## Topic 3: Deployment Automation

### Why This Is Important

AuthKit can be secure in code but unsafe in deployment. Small deployment tiers increase this risk because one host may run AuthKit, PostgreSQL, Redis, direct email workers, and monitoring together.

Deployment automation reduces mistakes by making safe configurations repeatable:

- Operators know which environment variables are required.
- RabbitMQ can be disabled without breaking readiness.
- Redis or JDBC token mode is selected intentionally.
- SMTP or Resend is configured safely.
- Backups and restore checks are not forgotten.
- System services restart correctly.
- Health checks and metrics are available before a pilot.

This work also makes cost tiers real. A tier is not just a table in a document; it needs runnable configuration and operational procedures.

### Implementation Process

#### Step 1: Define Deployment Targets

Create `docs/runbooks/deployment-targets.md`.

Document targets:

- Local developer proof.
- Tier 00H micro VPS.
- Tier 0S solo VPS.
- Tier 1S larger solo VPS.
- Tier 0P PostgreSQL-only single instance.
- Tier 2M managed-light.

For each target, state:

- Required services.
- Optional services.
- Expected monthly cost range.
- User envelope.
- Availability risk.
- Token backend.
- Email mode.
- Email provider options.
- Backup responsibility.
- Monitoring responsibility.

#### Step 2: Add Docker Compose Stacks

Create `deploy/compose/`.

Minimum files:

```text
docker-compose.redis-direct.yml
docker-compose.jdbc-direct.yml
docker-compose.queue.yml
.env.redis-direct.example
.env.jdbc-direct.example
```

`docker-compose.redis-direct.yml` should include:

- AuthKit.
- PostgreSQL.
- Redis.
- Optional Mailpit for local SMTP testing.

`docker-compose.jdbc-direct.yml` should include:

- AuthKit.
- PostgreSQL.
- Optional Mailpit.
- No Redis.

Rules:

- Compose files must not contain real secrets.
- `.env.example` values must use `CHANGE-ME`.
- Production-only secrets must be referenced by environment variable.
- AuthKit container must expose health endpoint.
- PostgreSQL and Redis volumes must be named.
- Mailpit or a fake SMTP server must be clearly local-only.

#### Step 3: Add Systemd Units For VPS Tiers

Create `deploy/systemd/`.

Minimum files:

```text
authkit.service.example
authkit.env.example
authkit-backup.service.example
authkit-backup.timer.example
authkit-restore-check.service.example
```

`authkit.service.example` must:

- Run as a dedicated `authkit` user.
- Use `EnvironmentFile=/etc/authkit/authkit.env`.
- Set working directory explicitly.
- Restart on failure.
- Limit file descriptors reasonably.
- Use `NoNewPrivileges=true`.
- Use `ProtectSystem=strict` if compatible.
- Use `ReadWritePaths` for required directories.

Document exactly how to install:

```bash
sudo useradd --system --home /var/lib/authkit --shell /usr/sbin/nologin authkit
sudo mkdir -p /etc/authkit /var/lib/authkit /var/log/authkit
sudo chown -R authkit:authkit /var/lib/authkit /var/log/authkit
sudo install -m 600 docs/env/tier-0s-solo-vps.env.example /etc/authkit/authkit.env
```

The commands in docs must be examples. Do not run them automatically.

#### Step 4: Add Backup Scripts

Create `deploy/scripts/`.

Minimum scripts:

- `backup-postgres.sh`
- `restore-postgres-check.sh`
- `backup-redis.sh`
- `collect-diagnostics.sh`
- `preflight-config.sh`

`backup-postgres.sh` must:

1. Read `DB_URL`, `DB_USERNAME`, and backup directory.
2. Refuse to run without a configured backup directory.
3. Run `pg_dump` with a timestamped filename.
4. Write a checksum file.
5. Keep a retention window.
6. Never echo database passwords.

`restore-postgres-check.sh` must:

1. Create a temporary database.
2. Restore the latest backup.
3. Run basic table count checks.
4. Drop the temporary database.
5. Write a report.

`backup-redis.sh` must:

1. Be present only for Redis tiers.
2. Document whether Redis persistence is expected or whether session loss is accepted.
3. Refuse to run if Redis password is empty.

#### Step 5: Add Preflight Checks

`deploy/scripts/preflight-config.sh` must verify:

- Required environment variables exist.
- `AUTH_TOKEN_STORAGE_BACKEND=redis` has Redis host/password.
- `AUTH_TOKEN_STORAGE_BACKEND=jdbc` has `AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE=true`.
- Logging email provider is not selected.
- SMTP has TLS or SSL when selected.
- Resend has API key when selected.
- CORS origins are not wildcards.
- CSRF is enabled.
- Cookie secure flag is enabled.
- Argon2 settings are at or above floors.
- Scheduler lock settings are safe when jobs are enabled.

The script should not replace `ProductionConfigValidator`. It should catch mistakes before startup.

#### Step 6: Add Health And Readiness Runbook

Create `docs/runbooks/health-readiness.md`.

Explain:

- Which endpoint to call.
- Which metrics to inspect.
- What healthy looks like.
- What degraded Redis mode looks like.
- What degraded email provider looks like.
- What audit failures look like.
- What Hikari saturation looks like.
- What Argon2 saturation looks like.

Include commands:

```bash
curl -fsS "$AUTHKIT_BASE_URL/actuator/health"
curl -fsS "$AUTHKIT_BASE_URL/actuator/prometheus" | grep hikari
```

#### Step 7: Add Deployment Runbooks Per Tier

Create:

```text
docs/runbooks/tier-00h-micro-vps.md
docs/runbooks/tier-0s-solo-vps.md
docs/runbooks/tier-1s-solo-vps.md
docs/runbooks/tier-0p-postgres-only.md
```

Each runbook must include:

- Prerequisites.
- Host sizing.
- Firewall requirements.
- Package requirements.
- Environment file.
- Startup command.
- Smoke test command.
- Backup setup.
- Restore drill.
- Metrics check.
- Go/no-go criteria.
- Rollback procedure.

State obvious details, such as:

- Do not expose PostgreSQL or Redis publicly.
- Do not use default Redis password.
- Do not use HTTP frontend URLs in production.
- Do not keep `CHANGE-ME` values.
- Do not run Tier 0P with more than one AuthKit instance.

#### Step 8: Acceptance Criteria

This topic is complete when:

- Compose stacks exist for Redis and JDBC modes.
- Systemd examples exist.
- Backup and restore-check scripts exist.
- Preflight script exists.
- Health/readiness runbook exists.
- Tier runbooks exist.
- Scripts are shellcheck-clean if shellcheck is available.
- Local compose startup is tested for Redis-direct mode.
- Local compose startup is tested for JDBC-direct mode.

## Topic 4: Performance Tightening

### Why This Is Important

Performance work must not be guesswork. AuthKit's expensive paths are security-sensitive:

- Argon2 password verification.
- Refresh-token rotation.
- First-party session binding.
- Recovery token consume.
- MFA challenge consume.
- Email outbox polling.
- Audit event persistence.
- OAuth token issuance/introspection.

If these are tuned poorly, cheap tiers may fail under normal traffic or, worse, hostile traffic. If they are tuned by weakening security controls, AuthKit becomes cheaper but unsafe.

Performance tightening means measuring bottlenecks, setting conservative defaults, and documenting safe tuning bounds.

### Implementation Process

#### Step 1: Create A Performance Baseline Document

Create `docs/proof/performance-baselines.md`.

For each tier, document:

- JVM heap.
- CPU count.
- Hikari max pool.
- Argon2 memory.
- Argon2 iterations.
- Argon2 parallelism.
- Argon2 max concurrent.
- Token backend.
- Email mode.
- Email provider.
- Expected p95 latency.
- Expected bottleneck.
- Known unproven assumptions.

Mark every number as one of:

- `measured`
- `estimated`
- `operator-provided`
- `unknown`

Do not mix estimates with measured results.

#### Step 2: Add Microbenchmarks For Critical Components

Create `src/test/java/.../performance/` or `testing/proof/perf/`.

Prefer tests that can run locally without special infrastructure.

Minimum benchmarks:

- Argon2 encode and verify duration under configured memory.
- Redis token validate and rotate duration, using container tests when Docker is available.
- JDBC token validate and rotate duration.
- Session pagination with 100, 500, and 1,000 sessions.
- Email outbox claim and mark transitions.
- Audit synchronous event write.
- OAuth token issue and introspection decode.

These should not necessarily run in normal unit test CI. Add a Maven profile such as:

```bash
./mvnw -Pperformance-proof test
```

If JMH is added, document how to run it. If JMH is too heavy, use simple measured integration tests and mark them as approximate.

#### Step 3: Add Query Plan Checks

Create `testing/proof/perf/sql/`.

Add SQL files:

- `session-pagination-explain.sql`
- `refresh-rotation-explain.sql`
- `recovery-consume-explain.sql`
- `mfa-challenge-consume-explain.sql`
- `outbox-claim-explain.sql`
- `audit-insert-explain.sql`

Each file should:

1. Explain what query it tests.
2. Include required setup data count.
3. Run `EXPLAIN (ANALYZE, BUFFERS)` for PostgreSQL.
4. State which index should be used.

This matters because H2 tests do not prove PostgreSQL query plans.

#### Step 4: Tune Hikari By Tier

Use proof results to update `docs/env/*.env.example`.

Do not increase Hikari just because throughput looks low. More database connections can make a small VPS worse.

For each tier, record:

- `DB_POOL_MAX_SIZE`
- `DB_POOL_MIN_IDLE`
- Hikari pending thread behavior during load.
- PostgreSQL CPU/memory behavior.

Safe procedure:

1. Run proof with current value.
2. Record p95 and Hikari pending.
3. Increase by a small amount.
4. Run the same proof.
5. Compare.
6. Keep the smaller value unless the larger value clearly improves latency without causing DB pressure.

#### Step 5: Tune Argon2 Concurrency

Do not lower Argon2 memory, iterations, or parallelism below production floors.

Tune only concurrency:

- `SECURITY_ARGON2_MAX_CONCURRENT=0` means CPU-derived automatic sizing.
- Explicit values may be useful when the JVM, PostgreSQL, and direct email share a very small host.

Procedure:

1. Run login burst proof with automatic concurrency.
2. Record login p95/p99.
3. Record Argon2 saturation metric.
4. Record JVM heap and CPU.
5. Try explicit concurrency of `1`.
6. Try explicit concurrency of `2` only if CPU and memory allow.
7. Choose the setting that prevents uncontrolled queueing.

Never tune Argon2 based only on happy-path login speed. Consider credential stuffing.

#### Step 6: Tune Email Outbox

Direct email mode saves RabbitMQ cost but creates local worker pressure.

Measure:

- Outbox pending count.
- Processing count.
- Failed count.
- Dead count.
- Provider latency.
- Direct executor queue depth.
- Direct executor rejection count, if exposed.

Procedure:

1. Run registration/recovery burst.
2. Confirm rows move from `PENDING` to `PROCESSING` or `QUEUED` to `SENT`.
3. Simulate provider failure.
4. Confirm retry backoff.
5. Confirm terminal `DEAD` after max attempts.
6. Tune direct batch size and worker pool only after observing backlog.

Do not raise worker count beyond what provider and host can handle.

#### Step 7: Tune Session Pagination

For Redis mode:

- Confirm bounded `HSCAN` behavior.
- Test hundreds of sessions.
- Confirm no missing/duplicate sessions in stable dataset.
- Confirm cursor ownership.
- Confirm cursor expiry.

For JDBC mode:

- Confirm keyset pagination uses index.
- Test 100, 500, and 1,000 sessions.
- Confirm no unbounded table scan.
- Confirm cursor ownership and expiry.

#### Step 8: Define Performance Budgets

Create `docs/proof/performance-budgets.md`.

For each tier, define:

- Maximum expected registered users.
- Maximum expected DAU.
- Maximum login p95.
- Maximum refresh p95.
- Maximum session list p95.
- Maximum outbox backlog age.
- Maximum Hikari pending duration.
- Maximum audit dropped events: zero for critical, near-zero for noncritical.

Budgets must be updated only with measured proof or explicit risk acceptance.

#### Step 9: Acceptance Criteria

This topic is complete when:

- Performance baseline document exists.
- Critical component benchmarks exist.
- PostgreSQL query plan checks exist.
- Hikari tuning procedure is documented.
- Argon2 tuning procedure is documented.
- Email outbox tuning procedure is documented.
- Session pagination tuning procedure is documented.
- Performance budgets exist.
- At least one measured report updates the baseline.

## Topic 5: API/Contract Fixtures

### Why This Is Important

Integrations fail most often at boundaries:

- Wrong audience.
- Wrong issuer.
- Wrong token class.
- Missing tenant.
- Stale key.
- Expired token.
- Revoked session.
- OAuth token used as a first-party token.
- ID token used as an access token.
- Client-side authorization trusted by mistake.

API/Contract Fixtures make these mistakes testable before Wavern or another host is changed. They also protect AuthKit from regressions in token issuance, OpenAPI documentation, and security filters.

### Implementation Process

#### Step 1: Create Fixture Directory

Create `testing/proof/fixtures/tokens/`.

Suggested files:

```text
README.md
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
```

These JSON files should describe the token claims and expected behavior. They do not need to contain real signed JWTs unless the project also includes a deterministic test signer.

Each fixture must include:

```json
{
  "name": "wrong-audience",
  "tokenClass": "oauth_access",
  "claims": {},
  "expectedAuthKitResult": "rejected",
  "expectedIntegratorResult": "rejected",
  "reason": "aud does not match accepted resource audience"
}
```

#### Step 2: Add Deterministic Test Token Generator

Create `testing/proof/fixtures/generate-test-tokens.sh` or a Java test utility.

The generator must:

1. Use test-only RSA keys.
2. Refuse production keys.
3. Generate signed JWTs for each fixture.
4. Write output to a generated directory ignored by Git, such as `target/contract-fixtures/`.
5. Print a warning that tokens are test-only.

Do not commit generated signed JWTs unless they are clearly test-only and cannot be confused with production tokens.

#### Step 3: Add Contract Tests Against AuthKit APIs

Create tests that read fixtures and call AuthKit endpoints.

Minimum endpoint checks:

- `/api/v1/users/me` rejects OAuth access tokens.
- `/api/v1/users/me` rejects ID tokens.
- `/api/v1/users/me` rejects missing `token_use` unless legacy rules explicitly allow it.
- `/api/v1/users/me` rejects wrong audience.
- `/api/v1/users/me` rejects revoked session.
- `/oauth2/userinfo` accepts valid OAuth access token with `openid`.
- `/oauth2/userinfo` rejects first-party token.
- `/oauth2/introspect` rejects ID token and first-party token as active OAuth access.
- `/oauth2/revoke` ignores or rejects wrong token class safely.

These tests should be automated in the Maven suite if they are fast.

#### Step 4: Add Integrator Contract Tests

In the Integrator Sandbox sample, reuse the same fixtures.

The sample resource server must reject:

- ID tokens.
- First-party tokens.
- Wrong audience.
- Wrong issuer.
- Expired tokens.
- Missing tenant.
- Tenant mismatch.
- Missing scope.

This proves the fixtures are useful to both AuthKit and integrators.

#### Step 5: Add OpenAPI Contract Checks

The repository already validates OpenAPI. Extend the contract work so the spec includes:

- Token class expectations for each route.
- CSRF requirements for refresh/logout.
- Cookie behavior for refresh token.
- Session pagination response shape.
- OAuth userinfo/introspection/revocation token class rules.
- Error response examples for 400, 401, 403, 429, 503.

Then add or update tests to compare:

- Controller routes vs OpenAPI paths.
- HTTP methods.
- Required request parameters.
- Response DTO names.
- Security requirements.

Do not expose runtime Swagger UI unless separately approved.

#### Step 6: Add Negative Curl Collection

Create `testing/proof/smoke/negative-contracts.sh`.

This script must:

1. Load generated fixture tokens.
2. Call AuthKit endpoints.
3. Assert expected rejection.
4. Print a table of fixture, endpoint, expected status, actual status.

Example:

```text
fixture                          endpoint             expected  actual
oauth-token-used-on-first-party  /api/v1/users/me     401       401
id-token-used-on-userinfo        /oauth2/userinfo     401       401
wrong-audience                   /api/v1/users/me     401       401
```

#### Step 7: Add Fixture Documentation

Create `testing/proof/fixtures/README.md`.

Explain:

- What each fixture means.
- Which route should accept it.
- Which route should reject it.
- Which claim causes rejection.
- Whether the fixture is for AuthKit, an integrator, or both.

State the obvious:

- ID tokens are not API access tokens.
- OAuth access tokens are not AuthKit first-party user/admin tokens.
- First-party access tokens are not generic resource-server OAuth tokens unless a resource server explicitly accepts that class.
- Browser-held data is not authorization proof.
- Tenant claims must be checked server-side.

#### Step 8: Acceptance Criteria

This topic is complete when:

- Fixture metadata exists.
- Deterministic token generation exists.
- AuthKit negative contract tests exist.
- Integrator sandbox contract tests exist.
- OpenAPI route/security checks are updated.
- Negative curl script exists.
- Fixture documentation exists.
- All contract tests pass in CI.

## Recommended Execution Order

Do the work in this order:

1. API/Contract Fixtures.
2. Integrator Sandbox.
3. Deployment Automation.
4. AuthKit Proof Pack.
5. Performance Tightening.

Reason:

- Contract fixtures define what must be accepted and rejected.
- The sandbox uses those fixtures.
- Deployment automation gives repeatable environments.
- The proof pack runs against those environments.
- Performance tightening uses proof results instead of guesses.

## Milestones

### Milestone A: Contract Safety

Deliver:

- Fixture metadata.
- Token generator.
- Negative AuthKit token tests.
- OpenAPI security expectations.

Exit criteria:

- Wrong token class tests pass.
- Wrong audience/issuer tests pass.
- Revoked-session tests pass.

### Milestone B: Integrator Simulation

Deliver:

- Sample Spring resource server.
- Tenant enforcement.
- Scope/role checks.
- Positive and negative tests.

Exit criteria:

- The sample accepts only the intended token class.
- The sample rejects tenant breakout.
- The sample README can be followed by a developer who has not worked on AuthKit.

### Milestone C: Repeatable Deployment

Deliver:

- Compose stacks.
- Systemd examples.
- Preflight script.
- Backup and restore scripts.
- Tier runbooks.

Exit criteria:

- Redis-direct local stack starts.
- JDBC-direct local stack starts.
- Preflight catches missing secrets and unsafe settings.

### Milestone D: Proof Pack

Deliver:

- Smoke scripts.
- Load scripts.
- Chaos scripts.
- Metrics collector.
- Proof runner.
- Report template.

Exit criteria:

- One complete Tier 0S proof report exists.
- One complete Tier 0P proof report exists if Tier 0P remains enabled.

### Milestone E: Evidence-Based Tuning

Deliver:

- Performance baselines.
- Query plan checks.
- Component benchmarks.
- Tier budgets.
- Updated env defaults if evidence supports changes.

Exit criteria:

- Hikari, Argon2 concurrency, session pagination, and direct outbox settings have measured justification.

## Final Done Definition

This whole workstream is complete when AuthKit can answer these questions from repository-owned evidence:

- Which token classes can each API accept?
- Can a generic integrator validate AuthKit tokens correctly?
- Can a low-cost deployment start from documented automation?
- Can operators run smoke tests after deployment?
- Can operators run backup and restore checks?
- Can AuthKit prove Tier 0S and Tier 0P behavior under expected load?
- Can AuthKit show where bottlenecks are before production?
- Can AuthKit reject a production cutover when proof fails?

Until these questions are answered with artifacts, AuthKit may be feature-ready, but it is not fully proof-ready.
