# AuthKit Security Model

## Roles

- `ADMIN`: global platform administrator. Can view and manage all tenants, users, and OAuth clients. Production deployments must require current-password step-up plus MFA/passkey proof for every admin write. Passkeys are the preferred admin factor because they are phishing resistant; TOTP remains an accepted fallback with higher phishing risk.
- `TENANT_ADMIN`: tenant-scoped administrator. Can view users and OAuth clients only inside its own `tenant_id`. Cannot create, update, demote, promote, or disable global admins or other tenant administrators. Cannot manage global OAuth clients.
- `OWNER`: tenant owner identity for future product-level ownership flows. It has normal self-service account access in the current API and is not admitted to the admin plane.
- `USER`: standard self-service identity. Can access only `/api/v1/users/me/**` resources tied to its own JWT subject and tenant.

## Object Authorization

Hibernate tenant filtering is defense-in-depth only. Service methods that load objects by direct identifiers must enforce object-level authorization before returning or mutating data. AuthKit uses `404`-style not-found failures for cross-tenant self-service access and access-denied failures for explicit admin-plane policy violations.

## Session Revocation

AuthKit access JWTs are bound to the refresh-session `jti`. Authenticated requests are accepted only while that `jti` remains present in the server-side token store. Logout, logout-all, password reset, account deletion, session revocation, role changes, and refresh-token family compromise therefore deny affected access tokens before their natural expiry.

## Abuse Controls

High-risk public and authenticated endpoints have route-specific abuse throttles in addition to the global IP rate limiter. Policies cover login, MFA login verification, passkey assertion, registration, email-confirmation resend, password recovery request/reset, refresh, OAuth authorize/token/revoke/introspect, admin writes, profile writes, MFA changes, passkey changes, and account deletion. Dimensions include IP, device/user-agent, email/account, tenant, client id, or user id depending on the flow.

Redis-backed throttles are preferred for horizontal fairness. If Redis is unavailable, high-risk policies use stricter local Caffeine limits and emit `security.abuse_control.degraded`; account lockout similarly emits `security.lockout.degraded` while falling back to per-node lockout state. These degraded states are security incidents, not normal operating mode.

## JWT And Downstream Validation

AuthKit signs JWTs with the active RSA key and publishes the active public key plus configured retiring public keys in JWKS. Emergency-revoked key IDs are not published and are rejected by AuthKit's resource server decoder. Downstream services must validate `iss`, `aud`, `exp`, `nbf` where present, signature, `alg=RS256`, `kid`, `tenant_id`, scopes/authorities, and any application-specific authorization context. Downstream JWKS caches should refresh on unknown `kid` during rotation and should reject tokens signed by unrecognized or revoked keys.

## OAuth/OIDC Provider Boundaries

AuthKit implements the provider role for authorization-code + PKCE. OAuth access tokens are client-audience tokens and can be revoked by `jti`; introspection and userinfo are available for integrations that require them. Confidential client secrets are returned once at creation or rotation and are stored only as slow password hashes. AuthKit does not implement social-login federation in this service role.

## CORS And Internal Worker Access

CORS is configured explicitly in the application and production startup rejects unsafe wildcard-with-credentials or non-HTTPS origins. Internal worker endpoints require both a trusted source network and `X-Worker-Token`; a previous-token list supports rotation. Prefer mTLS or workload identity at the platform layer where available.
