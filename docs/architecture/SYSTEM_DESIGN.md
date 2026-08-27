# AuthKit v0.1 system design

[Português (Brasil)](SYSTEM_DESIGN-ptBR.md) | English is normative.

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

## Token classes and revocation

| Class | `token_use` | Audience | Revocation |
| --- | --- | --- | --- |
| First-party access | `first_party_access` | configured API | session/JTI checked inside AuthKit; external offline consumers bounded by ≤300 s expiry |
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
