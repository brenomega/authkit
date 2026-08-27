# Cross-site OAuth/OIDC example

Register an AuthKit public client with this page's exact HTTPS callback URI and scopes `openid email profile sample.read`. Configure `window.AUTHKIT_ISSUER`, `window.AUTHKIT_CLIENT_ID`, and `window.RESOURCE_URL` before loading `app.js`.

The page demonstrates Authorization Code with PKCE S256, unpredictable and expiring `state`/`nonce`, immediate callback URL cleanup, memory-only access/ID/refresh tokens, OAuth refresh rotation, resource calls, standard revocation, and error handling. Only short-lived PKCE ceremony material uses `sessionStorage`, because a full-page redirect must resume it; it is removed before token exchange.

Run it with `samples/resource-server-spring`. That server validates signature through JWKS, exact issuer/audience, expiry and `token_use=oauth_access`; Nimbus refreshes JWKS for an unknown `kid` and rejects if it remains unknown. The browser's nonce comparison is an additional binding check, not a replacement for cryptographic ID-token validation by a reviewed OIDC library or backend. This sample deliberately has no production UI, branding, client-secret storage, or generalized component library.
