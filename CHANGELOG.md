# Changelog

All notable changes are documented here. AuthKit uses Semantic Versioning; compatibility is maintained within `0.1.x`, and a future `0.2.0` may include documented breaking changes.

## [0.1.0-rc.1] - Unreleased

This is an unpublished implementation candidate for independent audit. It is not a release, tag, production approval, or risk acceptance.

### Added

- First-party authentication, rotating sessions, MFA, passkeys, Google and allowlisted generic OIDC federation.
- OAuth 2.0/OIDC Authorization Code with PKCE S256, resumable server-side authorization/consent transactions, opaque rotating OAuth refresh families, userinfo, introspection, revocation, discovery, and JWKS.
- Secure email change, suspension/reactivation, deletion grace/cancellation, irreversible anonymization, retention-only audited deletion, and a secret-free versioned user export.
- Offline one-shot first-administrator bootstrap and a `PLATFORM_ADMIN` control plane with signed pagination cursors and local step-up.
- Durable authentication email outbox, restricted operator-owned templates, provider-acceptance semantics, auditing, metrics, golden-path deployment, executable examples, and proof tooling.
- Apache-2.0 licensing, DCO contribution policy, security reporting, governance, support, and community conduct policies.

### Changed

- Roles are restricted to `USER` and `PLATFORM_ADMIN`; `tenant_id` is an opaque per-person partition and OAuth clients are instance-global.
- Session and administrative listings use bounded signed cursors without PII.
- Email confirmation tokens use URL fragments and JSON-body submission.
- Recovery-token lookup identifiers use keyed digests.
- Production defaults require Redis 7, direct durable outbox dispatch, SMTP TLS or explicit Resend selection, HIBP, strict proxy/origin configuration, and access-token TTL no greater than 300 seconds.

### Security

- First-party access, OAuth access, and ID token classes require explicit, mutually exclusive `token_use` values.
- Test keys and the test profile are confined to test resources and excluded from production artifacts and Docker build context.
- One-time confirmation, recovery, authorization, refresh, email-change, and passkey-counter boundaries are concurrency-safe and fail closed across the supported Redis/PostgreSQL path.
- Critical audit persistence participates synchronously in the protected mutation transaction.
