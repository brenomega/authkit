# AuthKit security model

[Português (Brasil)](SECURITY_MODEL-ptBR.md) | English is normative.

## Roles

AuthKit has exactly two account roles:

- `USER` is the normal account role.
- `PLATFORM_ADMIN` is an instance-wide operator role. Every administrative write requires a fresh step-up and a second factor. The final active platform administrator cannot be demoted, suspended, anonymized, or deleted; PostgreSQL also serializes and enforces this invariant.

There are no organization, owner, or tenant-administrator roles. OAuth clients are global resources of the AuthKit instance and only platform administrators manage them.

## Personal partition identifier

Every account receives an opaque, unique `tenant_id`. This identifier is only a personal data-partition key used for defense in depth and token/resource correlation. It does not represent a company, team, subscription, shared tenant, authorization boundary between members, or SaaS organization. Integrators needing organizations must model membership and authorization in their own domain.

The Hibernate partition filter is defense in depth. Service methods still enforce subject/resource ownership explicitly and use non-enumerating failures where appropriate.

## Account lifecycle

The durable account states are `ACTIVE`, `SUSPENDED`, `DELETION_PENDING`, and `ANONYMIZED`. Only active, email-confirmed accounts receive first-party runtime authorities. Suspension revokes active AuthKit sessions immediately; reactivation never restores revoked sessions. Anonymization is irreversible and removes direct profile identifiers and local password material.

## Credentials and authenticators

The local password is nullable because an account may be social-only. A missing password is never treated as an empty password. Password, passkey, TOTP, recovery, linking, and unlinking operations must preserve the last-authenticator invariant and require the step-up appropriate to the authenticator actually present.

## Token classes

Every accepted JWT must contain an explicit `token_use`. `first_party_access`, `oauth_access`, and `id_token` are separate classes with distinct audiences and consumers. AuthKit first-party APIs additionally require the JWT `jti` to identify a live server-side session. OAuth access tokens are never accepted by first-party user or admin routes.

## Edge and abuse controls

High-risk endpoints use route-specific throttles in addition to the global IP limiter. Production configuration must define explicit HTTPS origins and trusted proxy/CDN peers. Client-supplied forwarding headers are not trusted outside those peers.
