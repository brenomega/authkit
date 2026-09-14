# Cross-site OAuth/OIDC example

Register an AuthKit public client with this page's exact HTTPS callback URI and scopes `openid email profile sample.read`. Configure `window.AUTHKIT_ISSUER`, `window.AUTHKIT_CLIENT_ID`, and `window.RESOURCE_URL` before loading `app.js`.

The page demonstrates Authorization Code with PKCE S256, unpredictable and expiring `state`/`nonce`, immediate callback URL cleanup, memory-only access/ID/refresh tokens, OAuth refresh rotation, resource calls, standard revocation, and error handling. Only short-lived PKCE ceremony material uses `sessionStorage`, because a full-page redirect must resume it; it is removed before token exchange.

ID tokens are verified before any claim is trusted with the pinned JOSE 6.1.0 ESM build: RS256 signature through the issuer JWKS, exact issuer and client audience, time claims, required claims, non-empty `kid`, `token_use=id_token`, and ceremony nonce. The remote JWKS resolver performs a fresh fetch for an unknown `kid` and rejects it if still unpublished. Consequently wrong issuer, audience, expiry, nonce, algorithm or key ID all fail the callback; there is no raw JWT decode path. Pin and self-host the reviewed dependency for production instead of depending on the demonstration CDN URL.

Run it with `samples/resource-server-spring`. That server independently validates the access-token signature through JWKS, exact issuer/audience, expiry and `token_use=oauth_access`; Nimbus refreshes JWKS for an unknown `kid` and rejects if it remains unknown. This sample deliberately has no production UI, branding, client-secret storage, or generalized component library.
