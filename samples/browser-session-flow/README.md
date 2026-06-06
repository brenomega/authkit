# Browser Session Flow

This document shows how a browser client should interact with AuthKit. It applies to generic host systems, not only Wavern.

## Login

The login endpoint returns a short-lived access token and sets a refresh cookie:

```bash
curl -i -X POST "${AUTHKIT_BASE_URL}/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"correct horse battery staple"}'
```

Expected behavior:

- The access token is returned in the JSON body.
- The refresh token is set as an `HttpOnly`, `Secure`, `SameSite=Strict` cookie scoped to AuthKit auth routes.
- The browser stores the access token in memory only.
- The browser does not store refresh tokens, MFA challenges, authorization codes, or reset tokens in `localStorage`.

## Refresh

The browser sends cookies and echoes the readable CSRF cookie value in the configured CSRF header:

```bash
curl -i -X POST "${AUTHKIT_BASE_URL}/api/v1/auth/refresh" \
  -H "X-XSRF-TOKEN: ${CSRF_COOKIE_VALUE}" \
  --cookie "Refresh-Token=<http-only-cookie-is-sent-by-browser>"
```

If the CSRF header is absent or mismatched, refresh must fail. JavaScript should never read the refresh token itself.

## Logout

Logout revokes the current refresh session and clears the refresh cookie:

```bash
curl -i -X POST "${AUTHKIT_BASE_URL}/api/v1/auth/logout" \
  -H "X-XSRF-TOKEN: ${CSRF_COOKIE_VALUE}" \
  --cookie "Refresh-Token=<http-only-cookie-is-sent-by-browser>"
```

Use logout-all only for an authenticated user action that intentionally revokes every active session.

## Password Reset

Reset links must place the token in the URL fragment:

```text
https://app.example/reset-password#token=<reset-token>
```

The frontend reads the fragment once, removes it with `history.replaceState`, and sends the token in the reset request body. Query strings are not approved because proxies, access logs, and analytics tools commonly record them.

## OAuth Browser Flows

For OAuth/OIDC clients:

- Use authorization-code + PKCE.
- Treat the ID token as an authentication result only.
- Use the OAuth access token for resource APIs only when `token_use=oauth_access`, issuer, audience, expiry, tenant, and scope all validate.
- Do not send first-party AuthKit tokens to host resource APIs.

## Error Handling

Authentication errors should be user-safe and opaque. Do not display whether an email exists, whether a reset token was valid, or whether a lockout was created. The host can use AuthKit audit events and metrics for operator visibility.
