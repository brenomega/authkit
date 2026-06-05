# AuthKit Integrator Guide

## Token Classes

AuthKit issues three mutually exclusive JWT classes. Consumers must validate `alg=RS256`, `iss`, `aud`, expiry, `kid`, and `token_use` before trusting claims.

| `token_use` | Audience | Required claims | Intended use |
| --- | --- | --- | --- |
| `first_party_access` | Configured API audience | `sub`, `jti`, `tenant_id`, `amr`, `mfa` | AuthKit user/admin APIs; the Redis session identified by `jti` must remain active |
| `oauth_access` | OAuth client ID | `sub`, `jti`, `tenant_id`, `client_id`, `scope`, `amr` | Client resource APIs, userinfo, introspection, revocation |
| `id_token` | OAuth client ID | `sub`, `jti`, `tenant_id`, `amr`, optional `nonce` | Client authentication result only; never use as an API bearer token |

Legacy first-party tokens without `token_use` are temporarily accepted only when the configured API audience is present and OAuth-only claims are absent. Legacy OAuth access tokens require both `client_id` and `scope`. Remove this compatibility after the maximum legacy token TTL has elapsed.

For first-party access tokens, `amr` lists completed authentication methods and `mfa` is true when a method beyond password-only authentication participated. OAuth access and ID tokens expose `amr`; OAuth authorization is enforced through `client_id`, exact audience, and server-side `scope` checks rather than a first-party session lookup.

## Browser Session Handling

The refresh token is an `HttpOnly`, `Secure`, `SameSite=Strict` cookie scoped to `/api/v1/auth`. Browser clients must send credentials and echo the readable CSRF cookie in the configured CSRF header for refresh and logout. Do not store access, refresh, MFA challenge, authorization-code, or reset tokens in `localStorage`.

Password reset links place the token in the URL fragment. The frontend reads the fragment once, removes it with `history.replaceState`, and submits it in the reset request body. Fragments must never be forwarded to analytics or logs.

## JWKS And Validation

Cache `/.well-known/jwks.json` for a short bounded period. On an unknown `kid`, refresh once and reject if the key is still absent. Never accept an algorithm selected only from the token header. Validate the exact audience for the receiving API, enforce `tenant_id` against the request/resource tenant, and enforce OAuth scopes server-side.

Spring resource-server example:

```java
NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(issuer + "/.well-known/jwks.json").build();
decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
        JwtValidators.createDefaultWithIssuer(issuer),
        new JwtClaimValidator<List<String>>("aud", aud -> aud != null && aud.contains(requiredAudience)),
        new JwtClaimValidator<String>("token_use", "oauth_access"::equals)));
```

Refresh JWKS on key rotation, keep retiring keys until all issued tokens expire, and treat revoked keys as an emergency deny list supplied out of band to downstream services.
