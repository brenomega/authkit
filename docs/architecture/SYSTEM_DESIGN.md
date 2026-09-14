# AuthKit v0.1 system design

[English](SYSTEM_DESIGN.md) | [Português (Brasil)](SYSTEM_DESIGN-ptBR.md)

English is authoritative when translations differ.

## Trust and data boundaries

```mermaid
flowchart LR
  Browser[Browser application] -->|TLS, cookies + CSRF or OAuth PKCE| Proxy[Caddy trusted peer]
  Client[OAuth/OIDC client] -->|TLS, standard wire formats| Proxy
  Proxy -->|fixed peer, overwritten forwarding headers| AK[AuthKit]
  AK -->|runtime DML| PG[(PostgreSQL 17)]
  AK -->|sessions, one-time state, abuse controls| Redis[(Redis 7)]
  AK -->|durable direct outbox| Mail[SMTP TLS or Resend]
  Retention[Restricted retention worker] -->|SECURITY DEFINER functions only| PG
  Resource[Resource server] -->|JWKS + optional live internal introspection| AK
```

The browser never receives provider tokens after federation. First-party refresh tokens are HttpOnly same-site cookies protected by double-submit CSRF; access tokens are short-lived and memory-only. Cross-site OAuth clients use Authorization Code with state, nonce, exact redirect URI, and PKCE S256. OAuth refresh tokens are opaque rotating credentials tied to a locked family. `tenant_id` partitions one person's records and carries no organization authority.

## Internal dependency direction

```mermaid
flowchart LR
  HTTP[Controllers and security filters] --> APP[Lifecycle/application services]
  JOBS[Schedulers and offline commands] --> APP
  APP --> DOMAIN[Entities, invariants and value objects]
  APP --> PORTS[Repository, token-store, mail and audit ports]
  PORTS --> SQL[JPA/JDBC adapters]
  PORTS --> CACHE[Redis/JDBC token adapters]
  PORTS --> PROVIDERS[SMTP, Resend and OIDC adapters]
  SQL --> PG[(PostgreSQL)]
  CACHE --> REDIS[(Redis)]
```

Transport code does not call persistence adapters directly. Services own transaction boundaries; critical audit and SQL business state share the same transaction, while non-transactional revocation/cache cleanup is registered only after commit. Domain code does not depend on Spring MVC, Redis, SMTP or provider wire formats.

## Data ownership

```mermaid
erDiagram
  USER ||--o{ CONSENT_EVENT : records
  USER ||--o{ SECURITY_EVENT : subject
  USER ||--o{ PASSKEY_CREDENTIAL : owns
  USER ||--o{ MFA_CREDENTIAL : owns
  USER ||--o{ SOCIAL_IDENTITY : links
  USER ||--o{ OAUTH_CONSENT : grants
  USER ||--o{ OAUTH_REFRESH_FAMILY : owns
  USER ||--o{ ONE_TIME_STATE : binds
  EMAIL_OUTBOX }o--|| USER : notifies
```

PostgreSQL is authoritative for users, lifecycle state, consents, OAuth families, WebAuthn counters, durable email, and audit. Redis owns expiring first-party sessions, distributed abuse/lockout state, and selected one-time claims; its keys carry user/tenant binding and TTL. Provider tokens are validated and discarded rather than persisted.

## Deployment variants

```mermaid
flowchart TB
  subgraph Golden[Golden GA deployment]
    C[Caddy TLS/reverse proxy] --> A1[AuthKit]
    A1 --> P1[(PostgreSQL 17)]
    A1 --> R1[(Redis 7)]
    A1 --> E1[SMTP TLS or Resend]
  end
  subgraph Scale[Unsupported scale-out planning topology]
    LB[Trusted proxy/load balancer] --> A2[AuthKit replica A]
    LB --> A3[AuthKit replica B]
    A2 & A3 --> P2[(PostgreSQL 17)]
    A2 & A3 --> R2[(Redis 7 required)]
  end
  subgraph Experimental[Explicitly experimental]
    A4[Single AuthKit instance] --> P3[(PostgreSQL 17)]
    A4 --> J[JDBC token storage]
  end
```

The golden Compose topology is the fresh-install reference. Same-site browser and cross-site OAuth layouts differ in cookie/CORS behavior, not in trust of forwarded headers. JDBC token storage is restricted to one application instance and is never substituted when a gate requires real Redis.

## Identity lifecycle

```mermaid
stateDiagram-v2
  [*] --> ACTIVE: verified local/social identity
  ACTIVE --> SUSPENDED: platform admin + local step-up
  SUSPENDED --> ACTIVE: platform admin reactivation
  ACTIVE --> DELETION_PENDING: user request, sessions revoked
  DELETION_PENDING --> ACTIVE: strongly authenticated cancellation
  DELETION_PENDING --> ANONYMIZED: grace 0..30 days expires
  ANONYMIZED --> ANONYMIZED: repeat-safe purge processing
```

Anonymization is irreversible. Security/consent retention is bounded and append-only to the runtime role; deletion is available only to the separate retention role through audited procedures. The last active platform administrator is protected by service logic and a serialized PostgreSQL trigger.

## One-time and transactional boundaries

Registration confirmation and email-change tokens lock the owning user row. Recovery claims use atomic Redis Lua or locked JDBC state with finalize/release compensation. OAuth authorization transactions, codes, social state, nonce, PKCE verifiers, refresh rotation, and passkey counters are conditionally consumed or monotonically updated. Critical audit writes participate synchronously in the business transaction; failure aborts the mutation.

Email creation and business state commit with the durable outbox. Provider dispatch is outside that database transaction: SMTP performs one transport attempt per claim and the outbox owns retries; Resend adds bounded provider-idempotent retries. Provider acceptance and inbox delivery are distinct facts.

```mermaid
sequenceDiagram
  participant S as Lifecycle service
  participant PG as PostgreSQL
  participant W as Outbox worker
  participant M as SMTP/Resend
  S->>PG: Commit business mutation + PENDING email
  W->>PG: Claim due row with lease
  W->>M: Send with stable outbox idempotency identity
  alt Provider accepts
    W->>PG: Record ACCEPTED + provider message ID
  else Temporary failure
    W->>PG: Release with bounded backoff
  else Retry budget exhausted
    W->>PG: Mark DEAD and fire critical alert
  end
```

## Token classes and revocation

| Class | `token_use` | Audience | Revocation |
| --- | --- | --- | --- |
| First-party access | `first_party_access` | configured API | live session/JTI plus uncached PostgreSQL `session_version`; external offline consumers bounded by ≤300 s expiry |
| OAuth access | `oauth_access` | OAuth client | client/family/JTI revocation and authenticated introspection |
| OIDC ID token | `id_token` | OAuth client | authentication statement only; never accepted as API bearer |

Missing or mismatched `token_use`, issuer, audience, signature, expiry, revoked/unknown `kid`, or token-class claims are rejected. JWKS publishes current and configured retiring public keys, never private material.

The complete endpoint contract is [OpenAPI](../openapi.yaml); operator duties and failure behavior are in [Operations](../OPERATIONS.md).

## Primary use cases

### First-party account and session

```mermaid
sequenceDiagram
  actor Person
  participant App as Same-site application
  participant AK as AuthKit
  participant PG as PostgreSQL
  participant R as Redis
  Person->>App: Register with accepted policy versions
  App->>AK: POST /api/v1/auth/register
  AK->>PG: User + consent + durable email outbox (one transaction)
  Person->>App: Open operator action_url fragment
  App->>AK: POST confirmation token in JSON body
  AK->>PG: Lock user, consume once, audit
  App->>AK: Login
  AK->>R: Create revocable rotating session
  AK-->>App: Access token in response; refresh/CSRF cookies
  App->>AK: Refresh with cookies + CSRF header
  AK->>R: Atomic rotation; replay revokes session
```

### Federation without email auto-link

```mermaid
sequenceDiagram
  actor Person
  participant UI as Operator UI
  participant AK as AuthKit
  participant IdP as Allowlisted OIDC provider
  UI->>AK: Start with providerKey
  AK-->>UI: Provider URL; server keeps state/nonce/PKCE
  UI->>IdP: Authenticate
  IdP->>AK: Exact callback with state + code
  AK->>IdP: Code exchange and signed ID-token validation
  AK->>AK: Resolve only by exact (issuer, subject)
  alt Existing identity
    AK-->>UI: First-party session
  else Matching email only
    AK-->>UI: Explicit link required; no automatic link
  end
  AK->>AK: Discard provider access/refresh/ID tokens
```

### OAuth/OIDC authorization

```mermaid
sequenceDiagram
  actor Person
  participant Client as External client
  participant AK as AuthKit
  participant UI as Operator login/consent UI
  Client->>AK: GET /oauth2/authorize + state + nonce + S256
  AK-->>UI: Signed opaque transaction handle
  Person->>UI: Login and approve/deny
  UI->>AK: Resume one-time transaction
  AK-->>Client: Exact redirect with code/error + state
  Client->>AK: POST /oauth2/token + code_verifier
  AK-->>Client: oauth_access + optional id_token + opaque refresh
  Client->>AK: Rotate refresh
  AK->>AK: Replay revokes the full family
```

### Administrative lifecycle and retention

```mermaid
sequenceDiagram
  actor Admin as PLATFORM_ADMIN
  participant AK as AuthKit
  participant PG as PostgreSQL
  participant RW as Retention worker
  Admin->>AK: Mutation + recent local password/MFA step-up
  AK->>PG: Lock target and last-admin guard
  AK->>PG: State mutation + critical audit in one transaction
  Note over AK,PG: Audit failure rolls back the mutation
  RW->>PG: Scoped SECURITY DEFINER purge function
  PG->>PG: Retention outcome appended; direct DELETE denied
```

All administrative searches use short-lived signed cursors bound to the query. Bootstrap of the first administrator is an offline one-shot command; it is not exposed through HTTP.

## Backup, restore and signing-key rotation

```mermaid
flowchart LR
  Freeze[Record candidate and UTC cutoff] --> Dump[pg_dump + Redis RDB]
  Dump --> Hash[SHA-256, encrypt and copy off-host]
  Hash --> Clean[Clean PostgreSQL/Redis host]
  Clean --> Restore[Restore PostgreSQL then Redis]
  Restore --> Verify[Flyway, row counts, sessions, audit chain and smoke]

  Current[Current signing key] --> Add[Configure new current + previous public key]
  Add --> Publish[Publish both kids in JWKS]
  Publish --> Issue[Issue only with new kid]
  Issue --> Retire[Wait maximum token lifetime]
  Retire --> Remove[Remove old private/public material]
```

Backup/restore is a clean-host exercise, not merely a dump command; checksums, encryption, Redis expiry behavior, Flyway state, audit integrity and application smoke are verified. Planned rotation publishes overlap before issuance changes. Emergency revocation removes the compromised `kid`, invalidates affected live state, and accepts the bounded availability impact; an unknown or revoked `kid` always fails closed. Procedures and evidence fields are in [Operations](../OPERATIONS.md) and the [proof playbook](../proof/README.md).
