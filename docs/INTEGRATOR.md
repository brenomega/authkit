# AuthKit integrator guide

[Português (Brasil)](INTEGRATOR-ptBR.md) | English is normative.

## Choose one browser topology

A same-site first-party application uses AuthKit login, a memory-only access token, and the `HttpOnly; Secure; SameSite=Strict` refresh cookie with the readable CSRF cookie echoed in the configured header. Follow `samples/first-party-same-site`.

A cross-site application is an OAuth/OIDC client. Use Authorization Code with state, nonce for `openid`, exact redirect URI, and PKCE S256. Keep ceremony state briefly in `sessionStorage`, remove callback parameters immediately, and keep issued tokens in memory; a production browser client should use a backend-for-frontend for durable refresh custody. Follow `samples/oauth-cross-site`.

Never store access, refresh, MFA, authorization-code, confirmation, recovery, or email-change credentials in `localStorage`. Operator action URLs carry one-time credentials in the URL fragment; remove the fragment with `history.replaceState` before submitting the credential in a JSON body. Fragments must not reach analytics or logs.

## Token classes

Every JWT must carry exactly one explicit `token_use`; missing or legacy values are rejected.

| `token_use` | Exact audience | Intended consumer | Required boundary |
| --- | --- | --- | --- |
| `first_party_access` | Configured AuthKit/API audience | AuthKit first-party user/admin APIs | `sub`, `jti`, personal `tenant_id`, `amr`; live AuthKit session |
| `oauth_access` | OAuth client ID | Client resource API, userinfo, authenticated introspection/revocation | `sub`, `jti`, `client_id`, `scope`, personal `tenant_id`; live client/family state |
| `id_token` | OAuth client ID | OIDC authentication result only | Never an API bearer; validate nonce when issued for an authorization request |

Consumers validate the configured algorithm, exact `iss`, expected `aud`, signature, expiry/not-before, `kid`, and exact token class before claims. `tenant_id` correlates one person's partition and is never organization authority. Host-product roles, organizations, subscriptions, and resource permissions belong to the integrator.

## JWKS and revocation

Cache `/.well-known/jwks.json` for a short bounded period. On unknown `kid`, refresh once and reject if still absent. Pin allowed algorithms independently of the token header. During planned rotation, keep retiring public keys until every issued token expires; exercise emergency removal separately.

AuthKit immediately revokes first-party sessions and OAuth families within its own live checks/introspection. A downstream resource server validating JWTs offline observes revocation no later than the access-token expiry (the golden recommendation is at most 300 seconds). Use authenticated first-party introspection only from trusted peers when a downstream requires live first-party status; use standard authenticated OAuth introspection for OAuth access tokens.

The Spring resource-server sample demonstrates issuer, audience, `token_use=oauth_access`, and scope validation. It deliberately does not convert `PLATFORM_ADMIN` into host-product authority or use `tenant_id` as an organization.

## Federation

Only providers allowlisted by a platform administrator are usable. AuthKit binds identities solely by exact `(issuer, subject)`. An equal email never auto-links accounts; the signed-in person must start an explicit link ceremony with local step-up. Unlinking cannot remove the final usable authenticator. Provider access, refresh, and ID tokens are discarded after the ceremony.

## Negative contract fixtures

Generate test-only fixtures under ignored `target/` and run boundary checks:

```sh
testing/proof/fixtures/generate-test-tokens.sh
AUTHKIT_BASE_URL=https://auth.example.test testing/proof/smoke/negative-contracts.sh
```

The fixtures use repository test keys and are never production credentials. The complete wire contract is `docs/openapi.yaml`; configuration and operator responsibilities are in `docs/CONFIGURATION.md` and `docs/OPERATIONS.md`.
