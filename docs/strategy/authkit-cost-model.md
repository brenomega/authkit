# AuthKit Cost Model For Integrator Deployments

Date: 2026-06-05

## Purpose

This document is the detailed cost and sizing companion to `docs/strategy/authkit-cost-reduction-wavern-plan.md`.

It exists so deployment-tier decisions are not made from vague labels like "cheap" or "standard." Wavern is the first concrete profile, but the tier model is intended for any system using AuthKit as an authentication engine. Every tier has:

- a monthly cost range,
- a registered-user range,
- a daily-active-user assumption,
- a bill-of-materials estimate,
- and explicit constraints.

These are planning envelopes, not measured production SLOs. Prompt 3 or an equivalent targeted proof must replace these estimates with measured capacity before production cutover.

## Pricing References

Prices were checked on 2026-06-05 and are listed before tax.

| Component | Reference price used | Source |
| --- | --- | --- |
| Small VPS | DigitalOcean Basic Droplets: `$12/month` for 2 GiB/1 vCPU, `$18/month` for 2 GiB/2 vCPU, `$24/month` for 4 GiB/2 vCPU, `$48/month` for 8 GiB/4 vCPU | https://www.digitalocean.com/pricing/droplets |
| VPS backups | DigitalOcean backup pricing: weekly backups at `20%` of droplet cost, daily backups at `30%` of droplet cost | https://www.digitalocean.com/pricing/droplets |
| Cost-optimized VPS | Hetzner price adjustment lists Germany/Finland CX23 at `$4.99/month`, CAX11 at `$5.49/month`, and US/Singapore CPX12 at `$9.49/month` after the 2026-04-01 adjustment | https://docs.hetzner.com/general/infrastructure-and-availability/price-adjustment/ |
| Cost-optimized VPS backups | Hetzner Cloud backups are billed as a `20%` monthly flat price for seven backup slots | https://docs.hetzner.com/cloud/billing/faq/ |
| Managed PostgreSQL | DigitalOcean managed PostgreSQL: `$15.15/month` for 1 GiB/1 vCPU, `$30.45/month` for 2 GiB/1 vCPU, `$60.90/month` for 4 GiB/2 vCPU | https://www.digitalocean.com/pricing/managed-databases |
| Managed Redis-compatible cache | DigitalOcean managed Valkey: `$15/month` for 1 GiB/1 vCPU, `$30/month` for 2 GiB/1 vCPU | https://www.digitalocean.com/pricing/managed-databases |
| Serverless Redis-compatible cache | Upstash Redis: free tier includes 256 MB and 500K commands/month; pay-as-you-go is `$0.20/100K commands`; fixed 250 MB starts at `$10/month` | https://upstash.com/pricing |
| Email sending | Amazon SES outbound email is `$0.10/1,000 emails` after applicable free tier; AWS notes 3,000 free message charges/month for eligible new accounts | https://aws.amazon.com/ses/pricing/ |
| Current AuthKit email provider | Resend free tier has a daily limit of 100 emails; dedicated IP add-on is `$30/month` | https://resend.com/pricing |
| Managed queue reference | CloudAMQP has a free shared tier and paid plans starting at `$19/month`; dedicated plans start higher | https://www.cloudamqp.com/plans.html |

Provider choice is not mandatory. The tier math uses these prices as concrete public baselines so the plan is auditable.

Price-volatility note: Hetzner has also announced updated cloud-server pricing for new orders and rescales starting 2026-06-15. Refresh Tier 00H numbers before procurement, especially if the selected region is outside Germany/Finland.

## Cost Scope

Included:

- AuthKit application compute.
- PostgreSQL.
- Redis or Redis-compatible token/session storage.
- Email sending for auth-related transactional email.
- Basic VPS backups where a VPS is used.
- Optional RabbitMQ/queue service only in higher tiers.

Excluded:

- Taxes, currency conversion, and regional price differences.
- The integrator's existing application hosting, such as Wavern's Supabase or business-application hosting.
- Domain, CDN, WAF, paid log retention, SIEM, SMS, and human operations time.
- Provider support plans.

## Workload Model

The user ranges below use registered users, not total contacts or marketing subscribers.

`Client` is ambiguous and must not be used for sizing without a definition. In this model, `100 clients` means `100 registered users`. If it means `100 customer companies`, use the total registered-user and DAU counts instead.

Baseline assumptions:

- `DAU = 20%` of registered users.
- Each DAU performs `1` login/day.
- Each DAU performs `6` refresh-token rotations/day.
- Each DAU performs `3` AuthKit-protected account/session/security reads/day.
- Each registered user has `2` active sessions on average.
- Auth-related email volume is `0.10 emails/DAU/day`.
- Redis/session data averages `<= 2 KB` per active session plus modest token metadata.
- Low-cost tiers use direct email dispatch through the durable PostgreSQL outbox.

Derived monthly estimates:

| Registered users | DAU | Logins/month | Refreshes/month | Auth reads/month | Auth emails/month | Active sessions | Redis data estimate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `100` | `20` | `600` | `3,600` | `1,800` | `60` | `200` | `< 1 MB` |
| `200` | `40` | `1,200` | `7,200` | `3,600` | `120` | `400` | `< 2 MB` |
| `500` | `100` | `3,000` | `18,000` | `9,000` | `300` | `1,000` | `< 5 MB` |
| `1,500` | `300` | `9,000` | `54,000` | `27,000` | `900` | `3,000` | `< 15 MB` |
| `7,500` | `1,500` | `45,000` | `270,000` | `135,000` | `4,500` | `15,000` | `< 75 MB` |
| `25,000` | `5,000` | `150,000` | `900,000` | `450,000` | `15,000` | `50,000` | `< 250 MB` |
| `50,000` | `10,000` | `300,000` | `1,800,000` | `900,000` | `30,000` | `100,000` | `< 500 MB` |

Why these ranges are conservative:

- Argon2 login hashing is the first bottleneck on very small VPS tiers, not Redis storage.
- PostgreSQL and JVM memory pressure matter more than token/session storage under 1,500 registered users.
- Email volume remains low because this model counts authentication emails, not product newsletters.
- Attack traffic is not modeled as normal capacity. Abuse controls must throttle it before it consumes Argon2 or DB capacity.

## Tier Cost And Capacity Table

| Tier | Bill of materials | Monthly cost before taxes | Registered users | DAU | Notes |
| --- | --- | --- | --- | --- | --- |
| Tier 00E: Existing-Host Sidecar | Existing paid host with spare CPU/RAM + isolated PostgreSQL + isolated Redis + direct email + `$0-$5` incremental backup/monitoring allowance | `$0-$5 incremental` | `1-100` | `1-20` | Cheapest only when another system already pays for suitable infrastructure. Shared-fate risk must be explicit. |
| Tier 00H: Cost-Optimized Micro VPS | `$4.99-$9.49` VPS + `20%` provider backups + `$0-$1` auth email | `$5.99-$12.39` | `1-100` | `1-20` | Uses provider-specific low-cost shared-vCPU plans. EU can be near `$5.99-$7.59`; US/Singapore are closer to `$11.39-$12.39`. |
| Tier 0S: Solo VPS Current-Code | `$12-$18` VPS + `20%` weekly backup + local PostgreSQL + local Redis + `$0-$1` auth email | `$14.40-$22.60` | `1-500` | `1-100` | Cheapest safe current-code tier. Use 2 GiB/1 vCPU for `1-200` users; prefer 2 GiB/2 vCPU for `201-500`. |
| Tier 1S: Larger Solo VPS Current-Code | `$24` VPS + `20%-30%` backup + local PostgreSQL + local Redis + `$0-$4` auth email | `$28.80-$35.20` | `501-1,500` | `101-300` | Still single-instance. More memory headroom for JVM, PostgreSQL, Redis, and direct email worker. |
| Tier 2M: Managed-Light Current-Code | `$24` app VPS + `20%` backup + `$15.15-$30.45` managed PostgreSQL + `$10-$15` managed/serverless Redis + `$0-$4` auth email | `$54.00-$79.00` | `1,501-7,500` | `301-1,500` | First tier where managed service cost dominates. Choose when operational isolation is worth the money. |
| Tier 3R: Resilient Direct-Email | `2 x $24` app VPS + `20%-30%` backups + `$30.45-$60.90` managed PostgreSQL + `$15-$30` managed Redis + `$0-$19` optional shared queue + `$1-$10` auth email | `$103.00-$183.00` | `7,501-25,000` | `1,501-5,000` | Better deploy resilience and horizontal app scaling. RabbitMQ still optional if direct outbox latency is acceptable. |
| Tier 4F: Full Production Baseline | `2 x $48` app VPS + `20%-30%` backups + `$60.90-$122.10` managed PostgreSQL + `$30-$60` managed Redis + `$19-$49` queue + `$5-$20` auth email + `$20-$50` observability/logging allowance | `$230.00-$400.00+` | `25,001-50,000+` | `5,001-10,000+` | Broad production baseline. Requires Prompt 3 measurement before treating capacity as real. |
| Tier 0P: PostgreSQL-Only Single-Instance | Same VPS/backups as Tier 0S + no Redis process/service + JDBC token storage | `$14.40-$22.60` | `1-300` | `1-60` | Implemented with explicit single-instance validation. It saves managed Redis cost only when Redis would otherwise be a paid separate service. |

## Why Tier 00H Can Be Cheaper Than Tier 0S

Tier 0S used DigitalOcean-style provider-neutral pricing. It is a conservative baseline, not the absolute cheapest possible VPS market price.

Tier 00H uses cost-optimized providers where a suitable shared-vCPU VPS can be far cheaper:

```text
$4.99  Hetzner EU CX23-style cost-optimized VPS
 $1.00 provider backup at 20%
 $0.00 auth email when under free provider limits
= $5.99/month before taxes
```

For a higher-priced US/Singapore region or a small email allowance:

```text
$9.49  low-cost regional VPS
 $1.90 provider backup at 20%
 $1.00 low auth email allowance
= $12.39/month before taxes
```

This tier is feasible only because AuthKit's current code already supports the important cost switches: no RabbitMQ, direct email, local PostgreSQL, local Redis, small Hikari pool, and CPU-derived Argon2 concurrency.

## Why Tier 0S Is Cheaper Than The Old Plan

The old plan implicitly assumed managed PostgreSQL and managed Redis, which pushed the cheapest concrete tier toward `$30-$60/month`.

Tier 0S changes the cost basis:

- PostgreSQL and Redis run locally on the same VPS.
- RabbitMQ is removed through existing direct outbox mode.
- Kubernetes is removed.
- Auth email volume stays inside free/very-low-cost transactional email limits.

This gives a concrete lower bound:

```text
$12.00  VPS, 2 GiB/1 vCPU
 $2.40  weekly VPS backup at 20%
 $0.00  local PostgreSQL
 $0.00  local Redis
 $0.00  auth email when under free provider limits
= $14.40/month before taxes
```

And a safer Tier 0S upper bound:

```text
$18.00  VPS, 2 GiB/2 vCPU
 $3.60  weekly VPS backup at 20%
 $1.00  low auth email allowance
= $22.60/month before taxes
```

Tier 1S crosses `$30/month` because it buys more memory:

```text
$24.00  VPS, 4 GiB/2 vCPU
 $7.20  daily VPS backup at 30%
 $4.00  auth email allowance
= $35.20/month before taxes
```

## Tier 00E And Tier 00H Constraints

Tier 00E is cheap because another system is already paying for infrastructure. It is acceptable only when:

- PostgreSQL is isolated by database or schema ownership.
- Redis is isolated by credentials, database number, or key prefix policy.
- JVM, PostgreSQL, and Redis resource ceilings are explicit.
- Host-level metrics can distinguish AuthKit pressure from host-application pressure.
- Shared-fate risk is accepted in writing.

Tier 00H is cheap because it uses shared-vCPU, provider-specific low-cost VPS capacity. It is acceptable only when:

- The registered-user count is `<=100`.
- Provider region, latency, data residency, abuse policy, and support posture are acceptable.
- Backups are enabled and restore-tested.
- Prompt 3 or a small targeted burst test is run before public production use.

## Tier 0S Constraints

Tier 0S is cheap because it accepts operational constraints:

- Single instance.
- Shared CPU and memory among JVM, PostgreSQL, Redis, and host processes.
- No automatic failover.
- Backups and restore drills are operator-owned.
- Host patching creates maintenance windows.
- Local Redis loss means token/session-state loss unless snapshots or persistence are configured and tested.

This is acceptable for HML and potentially for a very small production pilot with explicit risk acceptance. It is not acceptable for a high-availability production promise.

## Module Decisions

| Module | Tier 00E | Tier 00H | Tier 0S | Tier 1S | Tier 2M | Tier 3R | Tier 4F | Tier 0P |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PostgreSQL | Existing isolated | Local | Local | Local | Managed preferred | Managed | Managed | Local |
| Redis/token storage | Existing isolated Redis required | Local Redis required | Local Redis required | Local Redis required | Managed/serverless Redis | Managed Redis | Managed Redis | JDBC token storage, single-instance only |
| RabbitMQ | Disabled | Disabled | Disabled | Disabled | Disabled | Optional | Enabled or equivalent | Disabled |
| Email outbox | Enabled direct | Enabled direct | Enabled direct | Enabled direct | Enabled direct | Enabled direct or queue | Enabled queue/direct by SLO | Enabled direct |
| MFA/passkeys | Enabled when used | Enabled when used | Enabled when used | Enabled when used | Enabled when used | Enabled when used | Enabled when used | Enabled only after JDBC token challenge storage exists |
| CSRF/CORS/origin firewall | Enabled | Enabled | Enabled | Enabled | Enabled | Enabled | Enabled | Enabled |
| Audit logging | Enabled | Enabled | Enabled | Enabled | Enabled | Enabled | Enabled | Enabled |
| Argon2 floors | Production floors | Production floors | Production floors | Production floors | Production floors | Production floors | Production floors | Production floors |

## Decision Procedure

1. If an existing host has spare capacity and isolated PostgreSQL/Redis, choose Tier 00E for `<=100` registered users.
2. If the hard cost ceiling is below `$10-$12/month` and a cost-optimized provider is acceptable, choose Tier 00H for `<=100` registered users.
3. If the goal is HML or first integration proof with provider-neutral sizing, choose Tier 0S.
4. If the deployment must support more than `500` registered users but still has a hard low-cost target, choose Tier 1S.
5. If single-instance operation is not acceptable, choose Tier 3R or above.
6. If managed database backups are mandatory, choose Tier 2M or above.
7. If Redis is politically or operationally unacceptable, choose Tier 0P only for a single-instance deployment with `AUTH_TOKEN_STORAGE_BACKEND=jdbc` and `AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE=true`.
8. If the integrator expects more than `25,000` registered users or AuthKit will serve multiple products, choose Tier 4F and run Prompt 3 first.

## Validation Required Before Production

For Tier 00E, Tier 00H, Tier 0S, or Tier 1S production pilot:

- Run the full Maven test suite.
- Run Redis container tests.
- Run PostgreSQL migration tests.
- Perform a restore drill from VPS backup and PostgreSQL dump.
- Run a small burst test for login, refresh, recovery, MFA login, and session listing.
- Confirm direct outbox retry/dead-message alerting.
- Confirm firewall rules expose only HTTP(S), SSH through controlled access, and necessary outbound email/provider traffic.
- For Tier 00E, confirm host-level isolation and shared-fate risk acceptance.
- For Tier 00H, confirm provider region, latency, data residency, and shared-vCPU behavior are acceptable.

For Tier 2M and higher:

- Also run Redis and PostgreSQL provider failure tests.
- Validate app restart and rolling deploy behavior.
- Validate alert routing for audit fail-closed, Redis degradation, email dead messages, Argon2 saturation, and scheduler failures.

For Tier 3R and Tier 4F:

- Run targeted Prompt 3 load, chaos, frontend, backup/restore, key-rotation, and incident-response proof.

## Update Rule

When any of these changes, update this document and `docs/strategy/authkit-cost-reduction-wavern-plan.md` together:

- AuthKit adds `JdbcTokenStorage`.
- AuthKit adds SES provider support beyond the implemented SMTP provider.
- An integrator chooses hosted Supabase, self-hosted Supabase, gateway JWT translation, backend-for-frontend, or direct resource-server validation.
- A tier is load-tested.
- Provider pricing changes enough to alter a tier by more than `$5/month`.
- The registered-user envelope for any tier changes.
