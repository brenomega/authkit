# Wavern AuthKit Integration Spec

Date: 2026-06-05

Status: Phase 2 discovery artifact. This document defines the intended Wavern/AuthKit boundary and the HML proof checklist. It does not claim that Wavern or hosted Supabase has already been configured.

## Recommended Boundary

AuthKit should remain an external authentication service and OAuth/OIDC provider. Wavern should treat AuthKit as the identity provider and should validate AuthKit-issued JWTs server-side before allowing business operations.

The recommended production boundary is:

- AuthKit owns authentication, refresh cookies, CSRF, MFA, passkeys, account recovery, password reset, session management, email verification, OAuth/OIDC metadata, and audit logs.
- Wavern owns business authorization, company membership, subscription state, product roles, tenant-resource checks, and UI routing.
- Wavern APIs accept only AuthKit OAuth access tokens for business resources.
- AuthKit first-party access tokens remain for AuthKit user/admin APIs.
- ID tokens are authentication result tokens only and must never authorize Wavern APIs.

## Token Policy

Wavern resource APIs must accept only tokens with:

| Claim | Required value |
| --- | --- |
| `alg` | `RS256` |
| `iss` | `AUTH_JWT_ISSUER`, for example `https://auth.example.com` |
| `aud` | Wavern OAuth client id or dedicated Wavern API audience |
| `token_use` | `oauth_access` |
| `client_id` | Wavern OAuth client id |
| `scope` | Includes the exact Wavern API scope required by the endpoint |
| `sub` | AuthKit user UUID |
| `tenant_id` | AuthKit tenant UUID |
| `jti` | Present and not revoked |
| `exp`, `iat` | Present and valid with bounded clock skew |

Wavern APIs must reject:

- `token_use=first_party_access`
- `token_use=id_token`
- tokens without `token_use`
- tokens signed by revoked `kid`
- tokens with AuthKit's first-party API audience instead of the Wavern audience
- tokens with missing or mismatched `tenant_id`
- tokens whose scopes do not authorize the requested operation

## Claims And Source Of Truth

AuthKit currently issues these relevant claims:

| Token class | Current claims |
| --- | --- |
| First-party access | `sub`, `jti`, `tenant_id`, `token_use=first_party_access`, `amr`, `mfa`, configured API `aud` |
| OAuth access | `sub`, `jti`, `tenant_id`, `token_use=oauth_access`, `client_id`, `scope`, `amr`, OAuth client `aud` |
| ID token | `sub`, `jti`, `tenant_id`, `token_use=id_token`, `amr`, optional `nonce`, optional `email`, optional `email_verified`, optional `name` |

Wavern target claims:

| Claim | Source | Current status |
| --- | --- | --- |
| `sub` | AuthKit user id | Already issued |
| `tenant_id` | AuthKit tenant id | Already issued |
| `empresa_id` | Wavern company id | Not currently issued by AuthKit |
| `wavern_role` | Wavern membership role | Not currently issued by AuthKit |
| `subscription_plan` | Wavern billing/subscription state | Not currently issued by AuthKit |

Phase 2 decision: do not block HML on embedding mutable Wavern authorization claims in AuthKit tokens. Wavern should validate `sub` and `tenant_id`, then load `empresa_id`, `wavern_role`, and `subscription_plan` from Wavern's own database. If these claims are later added to AuthKit tokens, add a dedicated claim-mapping service, sync contract, tests for stale role revocation, and a short token TTL review.

## OAuth/OIDC Flow

Preferred Wavern browser flow:

1. Wavern sends the user through AuthKit OAuth authorization code with PKCE.
2. AuthKit authenticates the user, including MFA/passkey challenge when required.
3. AuthKit returns an authorization code to Wavern.
4. Wavern exchanges the code at `/oauth2/token`.
5. Wavern receives an OAuth access token and, when `openid` is requested, an ID token.
6. Wavern APIs validate the OAuth access token server-side.
7. Wavern frontend stores no refresh token in localStorage. If a browser session is needed, use HttpOnly cookies or a backend-for-frontend session boundary.

AuthKit endpoints involved:

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `POST /api/v1/oauth2/authorize`
- `POST /oauth2/token`
- `POST /oauth2/revoke`
- `POST /oauth2/introspect`
- `GET /oauth2/userinfo`

## Supabase Feasibility

Official Supabase documentation checked on 2026-06-05 says Supabase can accept JWTs from other authentication servers through Third-Party Auth or externally minted/imported signing-key JWTs, and custom OAuth/OIDC providers can fetch discovery metadata and JWKS from an issuer.

References:

- https://supabase.com/docs/guides/auth/jwts
- https://supabase.com/docs/guides/auth/
- https://supabase.com/features/custom-oidc-providers

HML must still prove the exact Wavern project behavior. The minimum Supabase proof is:

- Configure AuthKit as a custom OIDC provider or accepted external JWT issuer in the hosted Supabase project, if the selected Supabase plan supports it.
- Pass an AuthKit OAuth access token to the Supabase client through the supported `accessToken` callback, not by hardcoding an Authorization header in client globals.
- Verify Supabase/PostgREST exposes the expected JWT claims to RLS policies.
- Verify `auth.uid()` or `auth.jwt()->>'sub'` maps to AuthKit `sub`.
- Verify `auth.jwt()->>'tenant_id'` is available for tenant RLS.
- Verify wrong tenant, wrong audience, ID-token, first-party-token, expired-token, and revoked-key tests fail closed.

Fallback order if hosted Supabase cannot safely trust AuthKit JWTs:

1. Keep Supabase as database only and put Wavern APIs behind a server-side resource layer that validates AuthKit tokens and uses service credentials to call Supabase.
2. Add a PostgREST/API gateway JWT translation layer that validates AuthKit tokens, derives Wavern claims, and presents a token format Supabase RLS accepts.
3. Self-host Supabase if hosted configuration cannot express the required issuer/JWKS/claim behavior.
4. Keep Supabase Auth only for database access and use AuthKit for Wavern API/session security during a temporary dual-auth transition.

## User Provisioning

Recommended HML path: just-in-time provisioning in Wavern.

On the first valid AuthKit OAuth access token:

1. Wavern validates the token.
2. Wavern upserts a local identity row keyed by `authkit_user_id=sub`.
3. Wavern links or creates the company membership for `tenant_id`.
4. Wavern loads `empresa_id`, `wavern_role`, and subscription data from its own tables.
5. If provisioning fails, Wavern denies the business request with an opaque retryable error and does not mutate AuthKit state.

Recommended local tables or equivalents:

| Table | Key fields |
| --- | --- |
| `auth_identities` | `authkit_user_id`, `email`, `tenant_id`, `created_at`, `last_seen_at` |
| `company_memberships` | `authkit_user_id`, `empresa_id`, `tenant_id`, `wavern_role`, `status` |
| `auth_migration_links` | `supabase_user_id`, `authkit_user_id`, `migration_status`, `linked_at` |

Future event-driven provisioning is allowed, but AuthKit does not currently expose a production webhook contract for Wavern. Do not invent unauthenticated callbacks. If webhooks are added, require signed delivery, idempotency keys, retries, audit events, and replay protection.

## Existing Supabase User Migration

Use a migration mode that does not require knowing user passwords:

1. Export existing Supabase Auth user ids and verified emails.
2. Create `auth_migration_links` rows with `supabase_user_id`, email, and pending `authkit_user_id`.
3. Ask users to authenticate through AuthKit by password reset/invite or through an approved federated provider.
4. On first AuthKit login, link by verified email with an explicit migration transaction.
5. Keep dual-auth read compatibility only for a bounded migration window.
6. Reject duplicate email collisions for manual review.
7. After cutover, revoke legacy Supabase client-side sessions and remove localStorage token usage.

Do not import password hashes unless Supabase hash format, AuthKit encoder support, and forced rehash-on-login behavior are fully documented and tested.

## HML Proof Checklist

- Create a Wavern OAuth client in AuthKit.
- Complete authorization code with PKCE from Wavern HML.
- Call one protected Wavern endpoint with an AuthKit OAuth access token.
- Confirm the endpoint rejects first-party access tokens.
- Confirm the endpoint rejects ID tokens.
- Confirm wrong audience and wrong client id fail.
- Confirm wrong tenant fails at both API and data-access layers.
- Confirm missing scope fails.
- Confirm AuthKit JWKS refresh works on unknown `kid`.
- Confirm revoked key id fails.
- Confirm token expiry and clock-skew behavior.
- Confirm Wavern derives `empresa_id`, `wavern_role`, and `subscription_plan` server-side.
- Confirm no AuthKit access or refresh token is stored in localStorage.
- Confirm refresh/logout CSRF handling works when Wavern calls AuthKit browser endpoints.
- Confirm registration/provisioning failure is idempotent and retryable.
- Confirm rollback path to previous Wavern auth flow is documented for HML only.

## Open Decisions

| Decision | Owner | Required evidence |
| --- | --- | --- |
| Hosted Supabase custom JWT/OIDC support path | Wavern/AuthKit integration | HML configuration proof and RLS negative tests |
| Wavern resource token audience | Wavern API owner | Exact OAuth client id or API audience used by validators |
| Provisioning source of truth | Wavern backend owner | Schema and idempotent upsert tests |
| Existing user migration window | Product/engineering | User count, communication plan, rollback threshold |
| Whether to add AuthKit Wavern custom claims | AuthKit owner | Claim freshness and role-revocation tests |
