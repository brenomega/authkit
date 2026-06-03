# AuthKit — Production Deployment & Secrets Management Guide

This document outlines the security specifications and infrastructure requirements for deploying the **AuthKit API** into a production environment, ensuring full compliance with technical requirements (DTs 3.1.26, 3.1.27, 3.2.2).

## 1. Secrets Protocol & Environment Variables

AuthKit is designed as a fully stateless, Twelve-Factor application. **No sensitive keys, credentials, or API tokens are hardcoded or tracked in version control.** All secrets must be injected at runtime using environment variables.

### Required Environment Variables

When deploying to a container orchestration service (e.g., Kubernetes, AWS ECS, Google Cloud Run) or a PaaS (e.g., Heroku, Vercel), provide the following variables:

#### Database (PostgreSQL)
* `DB_URL`: JDBC absolute URL for the PostgreSQL database (e.g., `jdbc:postgresql://db-host:5432/authkit_db`)
* `DB_USERNAME`: Database user
* `DB_PASSWORD`: Database password

#### RabbitMQ (Message Broker)
Required only when `AUTH_EMAIL_OUTBOX_DISPATCH_MODE=queue`, which is the default.

* `RABBIT_HOST`: Hostname of the RabbitMQ cluster
* `RABBIT_PORT`: AMQP Port (typically `5672`)
* `RABBIT_USERNAME`: Broker username
* `RABBIT_PASSWORD`: Broker password

#### Redis (Caching & Rate Limiting)
* `REDIS_HOST`: Hostname of the Redis server
* `REDIS_PORT`: Redis port (typically `6379`)
* `REDIS_PASSWORD`: Redis authentication password. Required in production because Redis stores refresh-token session state, MFA login challenges, and rate-limit counters.

#### Database Pool & Batching
* `DB_POOL_MAX_SIZE`: Maximum HikariCP connections per AuthKit instance. Default: `20`.
* `DB_POOL_MIN_IDLE`: Minimum idle HikariCP connections per instance. Default: `5`.
* `DB_POOL_CONNECT_TIMEOUT_MS`: Maximum wait for a pooled DB connection. Default: `3000`.
* `DB_POOL_IDLE_TIMEOUT_MS`: Idle connection timeout. Default: `600000`.
* `DB_POOL_MAX_LIFETIME_MS`: Maximum pooled connection lifetime. Default: `1800000`.
* `HIBERNATE_JDBC_BATCH_SIZE`: JDBC batch size for batched writes such as MFA backup-code regeneration. Default: `20`.

#### Security & Authentication
* `JWT_PUBLIC_KEY`: The absolute path to the RSA Public Key (`.pub` or `.pem`). This file must be mounted securely into the container.
* `JWT_PRIVATE_KEY`: The absolute path to the RSA Private Key (`.key` or `.pem`). This file must be mounted securely into the container.
* `AUTH_JWT_ISSUER`: Expected JWT issuer value. Must match the issuer used by downstream services validating AuthKit access tokens.
* `AUTH_JWT_AUDIENCE`: Expected JWT audience value. Downstream services should reject tokens not issued for this audience.
* `AUTH_JWT_KEY_ID`: Public key identifier published in JWKS and embedded in issued JWT headers.
* `AUTH_JWT_RETIRING_PUBLIC_KEYS`: Optional semicolon-separated retiring public keys, formatted as `kid=classpath:/key.pub`, `kid=file:/path/key.pub`, or `kid=-----BEGIN PUBLIC KEY-----...`. Use during signing-key rotation while old tokens are still valid.
* `AUTH_JWT_REVOKED_KEY_IDS`: Optional comma-separated key IDs to reject and hide from JWKS during emergency key revocation.
* `AUTH_ACCESS_TOKEN_TTL_SECONDS`: Access token lifetime in seconds. Default: `900`.
* `AUTH_REFRESH_TOKEN_TTL_DAYS`: Refresh-token-backed session lifetime in days. Default: `7`.
* `AUTH_RECOVERY_TOKEN_TTL_MINUTES`: Password recovery token lifetime in minutes. Default: `15`.
* `AUTH_AUTHORITY_CACHE_TTL_SECONDS`: Per-user authority cache TTL. Default: `30`; keep short because it trades revocation freshness for DB load reduction.
* `AUTH_AUTHORITY_CACHE_MAX_SIZE`: Maximum cached user authority snapshots per instance. Default: `10000`.
* `AUTH_MAX_REQUEST_BODY_BYTES`: Maximum accepted request body size before controller parsing. Default: `65536`.
* `AUTH_REFRESH_COOKIE_NAME`: Refresh cookie name. Default: `Refresh-Token`.
* `AUTH_REFRESH_COOKIE_PATH`: Refresh cookie path scope. Default: `/api/v1/auth`.
* `AUTH_REFRESH_COOKIE_HTTP_ONLY`: Whether the refresh cookie is `HttpOnly`. Production should keep this `true`.
* `AUTH_REFRESH_COOKIE_SECURE`: Whether the refresh cookie requires HTTPS. Production should keep this `true`.
* `AUTH_REFRESH_COOKIE_SAME_SITE`: SameSite policy for refresh cookies. Default: `Strict`.
* `AUTH_CSRF_ENABLED`: Enables stateless double-submit CSRF protection for cookie-backed refresh/logout endpoints. Default: `true`.
* `AUTH_CSRF_COOKIE_NAME`: Name of the readable CSRF cookie. Default: `XSRF-TOKEN`.
* `AUTH_CSRF_HEADER_NAME`: Header clients must echo from the CSRF cookie. Default: `X-XSRF-TOKEN`.
* `AUTH_CSRF_COOKIE_PATH`: CSRF cookie path scope. Default: `/api/v1/auth`.
* `AUTH_CSRF_TOKEN_BYTES`: Random bytes used before URL-safe Base64 encoding. Default: `32`.
* `AUTH_REGISTRATION_STEALTH_CONFLICTS`: When `true`, public registration returns the same generic `202 Accepted` acknowledgement for both new and duplicate emails. Production must keep this `true`.
* `AUTH_MFA_ENABLED`: Enables MFA runtime support. Default: `true`.
* `AUTH_MFA_BACKUP_CODE_COUNT`: Number of one-time backup codes generated per regeneration. Default: `10`.
* `AUTH_MFA_LOGIN_CHALLENGE_TTL_MINUTES`: Short TTL for one-time password-login MFA challenges stored in Redis. Default: `5`.
* `AUTH_MFA_SECRET_ENCRYPTION_KEY`: Secret material used to derive the AES-GCM key for encrypted TOTP secrets. Store only in a secret manager; minimum length is 32 characters.
* `AUTH_MFA_SECRET_ENCRYPTION_KEY_ID`: Stable key identifier written into new TOTP-secret encryption envelopes. Change this whenever `AUTH_MFA_SECRET_ENCRYPTION_KEY` is rotated.
* `AUTH_MFA_PREVIOUS_SECRET_ENCRYPTION_KEYS`: Optional semicolon-separated previous key material for decryption during rotation, formatted as `key-id=secret-material`. Keep previous keys only until all TOTP secrets have been re-encrypted.
* `AUTH_MFA_SECRET_ENCRYPTION_KDF_ITERATIONS`: PBKDF2-HMAC-SHA256 iterations for deriving per-secret AES-GCM keys. Production must keep this at or above `100000`; default is `210000`.
* `AUTH_MFA_STATUS_CACHE_TTL_SECONDS`: Short local cache TTL for whether a user has MFA enabled, reducing refresh/login DB reads. Default: `60`.
* `AUTH_MFA_STATUS_CACHE_MAX_SIZE`: Maximum cached MFA status entries per instance. Default: `10000`.
* `AUTH_PASSKEY_ENABLED`: Enables WebAuthn/passkey registration and login. Default: `true`.
* `AUTH_PASSKEY_RP_ID`: WebAuthn relying-party ID. In production this must be the registrable domain users see in the browser, e.g. `auth.example.com` or `example.com`.
* `AUTH_PASSKEY_RP_NAME`: Human-readable relying-party name shown by authenticators. Default: `AuthKit`.
* `AUTH_PASSKEY_ORIGINS`: Comma-separated allowed WebAuthn origins, e.g. `https://auth.example.com,https://app.example.com`.
* `AUTH_PASSKEY_CHALLENGE_TTL_MINUTES`: TTL for passkey registration/assertion challenges persisted in PostgreSQL. Default: `5`.
* `AUTH_PASSKEY_ALLOW_ORIGIN_PORT`: Allows non-default origin ports. Production should keep this `false` unless a controlled deployment needs it.
* `AUTH_PASSKEY_ALLOW_ORIGIN_SUBDOMAIN`: Allows subdomain origins under the RP ID. Production should keep this `false` unless every subdomain is equally trusted.
* `AUTH_OAUTH_PROVIDER_ENABLED`: Enables AuthKit's OAuth2/OIDC provider endpoints. Default: `true`.
* `AUTH_OAUTH_AUTHORIZATION_CODE_TTL_MINUTES`: TTL for one-time authorization codes. Default: `5`.
* `AUTH_OAUTH_ID_TOKEN_TTL_SECONDS`: ID token lifetime. Default: `900`.
* `AUTH_EMAIL_OUTBOX_ENABLED`: Enables the durable email outbox dispatcher. Default: `true`.
* `AUTH_EMAIL_OUTBOX_DISPATCH_MODE`: Email outbox dispatch mode. `queue` publishes through RabbitMQ before provider delivery; `direct` sends through a bounded direct provider worker pool. Default: `queue`.
* `AUTH_EMAIL_OUTBOX_BATCH_SIZE`: Maximum queue-mode email outbox messages claimed per poll. Default: `50`.
* `AUTH_EMAIL_OUTBOX_DIRECT_BATCH_SIZE`: Maximum direct-mode email outbox messages claimed per poll. Default: `5`.
* `AUTH_EMAIL_OUTBOX_POLL_DELAY_MS`: Dispatcher polling interval. Default: `5000`.
* `AUTH_EMAIL_OUTBOX_LOCK_TTL_SECONDS`: Time before an abandoned `PROCESSING` email is eligible for retry. Default: `300`.
* `AUTH_EMAIL_OUTBOX_DELIVERY_ACK_TIMEOUT_SECONDS`: Time a `QUEUED` external delivery may wait for provider acceptance before becoming claimable again. In queue mode this covers Rabbit listener acknowledgment; in direct mode this covers the async provider worker. Default: `600`.
* `AUTH_EMAIL_OUTBOX_SCHEDULER_POOL_SIZE`: Dedicated email outbox scheduler pool size. Default: `1`.
* `AUTH_EMAIL_OUTBOX_DIRECT_CORE_POOL_SIZE`: Core threads for direct provider dispatch workers. Default: `2`.
* `AUTH_EMAIL_OUTBOX_DIRECT_MAX_POOL_SIZE`: Maximum threads for direct provider dispatch workers. Default: `4`.
* `AUTH_EMAIL_OUTBOX_DIRECT_QUEUE_CAPACITY`: Bounded queue capacity for direct provider dispatch workers. Default: `100`.
* `AUTH_EMAIL_PROVIDER_TYPE`: Email provider implementation. Supported values: `resend`, `logging`. `logging` is intended for dev/test and is rejected in production. Default: `resend`.
* `AUTH_EMAIL_PROVIDER_CONNECT_TIMEOUT_MS`: Resend HTTP connect timeout. Default: `2000`.
* `AUTH_EMAIL_PROVIDER_READ_TIMEOUT_MS`: Resend HTTP read timeout. Default: `5000`.
* `AUTH_EMAIL_PROVIDER_MAX_ATTEMPTS`: Resend send attempts per provider delivery. Default: `3`.
* `AUTH_EMAIL_PROVIDER_RETRY_BACKOFF_MS`: Local backoff between Resend attempts. Default: `250`.
* `AUTH_EMAIL_PROVIDER_FROM`: Sender identity used by the configured provider.
* `AUTH_CORS_ENABLED`: Enables application-level CORS. Default: `true`.
* `AUTH_CORS_ALLOWED_ORIGINS`: Comma-separated explicit HTTPS browser origins allowed to call AuthKit. Required in production.
* `AUTH_CORS_ALLOWED_METHODS`: Allowed CORS methods. Default: `GET,POST,PATCH,DELETE,OPTIONS`.
* `AUTH_CORS_ALLOWED_HEADERS`: Allowed CORS headers. Default: `Authorization,Content-Type,X-XSRF-TOKEN,X-Worker-Token`.
* `AUTH_CORS_EXPOSED_HEADERS`: Exposed response headers. Default: `Location`.
* `AUTH_CORS_ALLOW_CREDENTIALS`: Whether browser credentials are allowed. Default: `true`; do not combine with wildcard origins.
* `AUTH_CORS_MAX_AGE_SECONDS`: Browser preflight cache duration. Default: `3600`.
* `AUTH_ABUSE_CONTROL_CAPACITY_MULTIPLIER`: Multiplier for endpoint/account throttle capacities. Production must keep this `1`; higher values are only for test suites or controlled non-production load exercises.
* `AUTH_TERMS_VERSION`: Current Terms of Use version recorded at registration.
* `AUTH_PRIVACY_POLICY_VERSION`: Current Privacy Policy version recorded at registration.
* `AUTH_LAWFUL_BASIS`: Lawful basis for account data processing. Allowed values include `consent`, `contract`, `legal_obligation`, `vital_interests`, `public_task`, and `legitimate_interests`.
* `AUTH_SECURITY_EVENT_RETENTION_DAYS`: Retention window for durable security events. Default: `365`.
* `AUTH_DELETED_ACCOUNT_RETENTION_DAYS`: Retention window for deleted account tombstones/anonymized records. Default: `30`.
* `AUTH_DATA_EXPORT_SECURITY_EVENT_LIMIT`: Maximum durable security events included in a user data export. Default: `100`.
* `AUTH_RETENTION_BATCH_SIZE`: Maximum rows purged per retention batch. Default: `500`.
* `AUTH_RETENTION_JOB_ENABLED`: Enables scheduled security-event retention cleanup. Default: `true`.
* `AUTH_RETENTION_JOB_CRON`: Cron expression for retention cleanup. Default: `0 30 3 * * *`.
* `AUTH_AUDIT_HASH_PEPPER`: Secret pepper used to HMAC audit identifiers and event hashes. Store only in a secret manager and rotate with a documented investigation plan.
* `AUTH_AUDIT_ASYNC_ENABLED`: Enables bounded asynchronous security-event persistence. Default: `true`.
* `AUTH_AUDIT_WRITER_CORE_POOL_SIZE`: Core writer threads for durable security events. Default: `2`.
* `AUTH_AUDIT_WRITER_MAX_POOL_SIZE`: Maximum writer threads for durable security events. Default: `4`.
* `AUTH_AUDIT_WRITER_QUEUE_CAPACITY`: Bounded in-memory queue for security-event writes. Default: `5000`.
* `AUTH_AUDIT_WRITER_SHUTDOWN_TIMEOUT_SECONDS`: Graceful shutdown wait for queued security events. Default: `10`.
* `AUTH_AUDIT_SYNC_ON_OVERLOAD`: Persists security events synchronously if the queue is saturated. Default: `true`.
* `WORKER_TOKEN`: Current shared internal worker token for `/actuator/prometheus` and `/api/v1/internal/**`.
* `WORKER_PREVIOUS_TOKENS`: Optional comma-separated previous worker tokens accepted during rotation.

#### External Integrations
* `RESEND_API_KEY`: API Token for the Resend email service. Required when `AUTH_EMAIL_PROVIDER_TYPE=resend`.
* `AUTH_FRONTEND_ACTIVATION_URL`: Public HTTPS frontend activation URL, without query string.
* `AUTH_FRONTEND_PASSWORD_RESET_URL`: Public HTTPS frontend password reset URL, without query string.

## 2. Secrets Management Strategy

### Option A: Local / Traditional Server Deployment (`.env` files)
For traditional deployments using `docker-compose` or systemd, create a `.env` file at the root level.
**WARNING:** The `.env` file must never be committed. Ensure it is listed in `.gitignore`.

```env
# Example .env file mapping
DB_URL=jdbc:postgresql://localhost:5432/authkit
DB_USERNAME=postgres
DB_PASSWORD=secret
RABBIT_HOST=localhost
RABBIT_USERNAME=admin
RABBIT_PASSWORD=secret
REDIS_HOST=localhost
REDIS_PASSWORD=replace-with-redis-password
DB_POOL_MAX_SIZE=20
DB_POOL_MIN_IDLE=5
DB_POOL_CONNECT_TIMEOUT_MS=3000
DB_POOL_IDLE_TIMEOUT_MS=600000
DB_POOL_MAX_LIFETIME_MS=1800000
HIBERNATE_JDBC_BATCH_SIZE=20
JWT_PUBLIC_KEY=file:/etc/authkit/keys/app.pub
JWT_PRIVATE_KEY=file:/etc/authkit/keys/app.key
AUTH_JWT_ISSUER=https://auth.example.com
AUTH_JWT_AUDIENCE=https://api.example.com
AUTH_JWT_KEY_ID=authkit-prod-key-1
AUTH_JWT_RETIRING_PUBLIC_KEYS=
AUTH_JWT_REVOKED_KEY_IDS=
AUTH_ACCESS_TOKEN_TTL_SECONDS=900
AUTH_REFRESH_TOKEN_TTL_DAYS=7
AUTH_RECOVERY_TOKEN_TTL_MINUTES=15
AUTH_AUTHORITY_CACHE_TTL_SECONDS=30
AUTH_AUTHORITY_CACHE_MAX_SIZE=10000
AUTH_MAX_REQUEST_BODY_BYTES=65536
AUTH_REFRESH_COOKIE_NAME=Refresh-Token
AUTH_REFRESH_COOKIE_PATH=/api/v1/auth
AUTH_REFRESH_COOKIE_HTTP_ONLY=true
AUTH_REFRESH_COOKIE_SECURE=true
AUTH_REFRESH_COOKIE_SAME_SITE=Strict
AUTH_CSRF_ENABLED=true
AUTH_CSRF_COOKIE_NAME=XSRF-TOKEN
AUTH_CSRF_HEADER_NAME=X-XSRF-TOKEN
AUTH_CSRF_COOKIE_PATH=/api/v1/auth
AUTH_CSRF_TOKEN_BYTES=32
AUTH_REGISTRATION_STEALTH_CONFLICTS=true
AUTH_MFA_ENABLED=true
AUTH_MFA_BACKUP_CODE_COUNT=10
AUTH_MFA_LOGIN_CHALLENGE_TTL_MINUTES=5
AUTH_MFA_SECRET_ENCRYPTION_KEY=replace-with-secret-random-mfa-encryption-key-at-least-32-chars
AUTH_MFA_SECRET_ENCRYPTION_KEY_ID=mfa-prod-key-2026-05
AUTH_MFA_PREVIOUS_SECRET_ENCRYPTION_KEYS=
AUTH_MFA_SECRET_ENCRYPTION_KDF_ITERATIONS=210000
AUTH_MFA_STATUS_CACHE_TTL_SECONDS=60
AUTH_MFA_STATUS_CACHE_MAX_SIZE=10000
AUTH_PASSKEY_ENABLED=true
AUTH_PASSKEY_RP_ID=auth.example.com
AUTH_PASSKEY_RP_NAME=AuthKit
AUTH_PASSKEY_ORIGINS=https://auth.example.com,https://app.example.com
AUTH_PASSKEY_CHALLENGE_TTL_MINUTES=5
AUTH_PASSKEY_ALLOW_ORIGIN_PORT=false
AUTH_PASSKEY_ALLOW_ORIGIN_SUBDOMAIN=false
AUTH_OAUTH_PROVIDER_ENABLED=true
AUTH_OAUTH_AUTHORIZATION_CODE_TTL_MINUTES=5
AUTH_OAUTH_ID_TOKEN_TTL_SECONDS=900
AUTH_EMAIL_OUTBOX_ENABLED=true
AUTH_EMAIL_OUTBOX_DISPATCH_MODE=queue
AUTH_EMAIL_OUTBOX_BATCH_SIZE=50
AUTH_EMAIL_OUTBOX_DIRECT_BATCH_SIZE=5
AUTH_EMAIL_OUTBOX_POLL_DELAY_MS=5000
AUTH_EMAIL_OUTBOX_LOCK_TTL_SECONDS=300
AUTH_EMAIL_OUTBOX_DELIVERY_ACK_TIMEOUT_SECONDS=600
AUTH_EMAIL_OUTBOX_SCHEDULER_POOL_SIZE=1
AUTH_EMAIL_OUTBOX_DIRECT_CORE_POOL_SIZE=2
AUTH_EMAIL_OUTBOX_DIRECT_MAX_POOL_SIZE=4
AUTH_EMAIL_OUTBOX_DIRECT_QUEUE_CAPACITY=100
AUTH_EMAIL_PROVIDER_TYPE=resend
AUTH_EMAIL_PROVIDER_CONNECT_TIMEOUT_MS=2000
AUTH_EMAIL_PROVIDER_READ_TIMEOUT_MS=5000
AUTH_EMAIL_PROVIDER_MAX_ATTEMPTS=3
AUTH_EMAIL_PROVIDER_RETRY_BACKOFF_MS=250
AUTH_EMAIL_PROVIDER_FROM="AuthKit Account <security@example.com>"
AUTH_CORS_ENABLED=true
AUTH_CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
AUTH_CORS_ALLOWED_METHODS=GET,POST,PATCH,DELETE,OPTIONS
AUTH_CORS_ALLOWED_HEADERS=Authorization,Content-Type,X-XSRF-TOKEN
AUTH_CORS_EXPOSED_HEADERS=Location
AUTH_CORS_ALLOW_CREDENTIALS=true
AUTH_CORS_MAX_AGE_SECONDS=3600
AUTH_ABUSE_CONTROL_CAPACITY_MULTIPLIER=1
AUTH_TERMS_VERSION=terms-v1
AUTH_PRIVACY_POLICY_VERSION=privacy-v1
AUTH_LAWFUL_BASIS=consent
AUTH_SECURITY_EVENT_RETENTION_DAYS=365
AUTH_DELETED_ACCOUNT_RETENTION_DAYS=30
AUTH_DATA_EXPORT_SECURITY_EVENT_LIMIT=100
AUTH_RETENTION_BATCH_SIZE=500
AUTH_RETENTION_JOB_ENABLED=true
AUTH_RETENTION_JOB_CRON="0 30 3 * * *"
AUTH_AUDIT_HASH_PEPPER=replace-with-secret-random-audit-pepper-at-least-32-chars
AUTH_AUDIT_ASYNC_ENABLED=true
AUTH_AUDIT_WRITER_CORE_POOL_SIZE=2
AUTH_AUDIT_WRITER_MAX_POOL_SIZE=4
AUTH_AUDIT_WRITER_QUEUE_CAPACITY=5000
AUTH_AUDIT_WRITER_SHUTDOWN_TIMEOUT_SECONDS=10
AUTH_AUDIT_SYNC_ON_OVERLOAD=true
WORKER_TOKEN=replace-with-secret-random-worker-token-at-least-32-chars
WORKER_PREVIOUS_TOKENS=
AUTH_FRONTEND_ACTIVATION_URL=https://app.example.com/activate
AUTH_FRONTEND_PASSWORD_RESET_URL=https://app.example.com/reset-password
RESEND_API_KEY=re_123456789
```

### Option B: Cloud-Native Secrets Management (Recommended)
For production safety, use external Secret Management services:
* **AWS:** Inject credentials via `AWS Secrets Manager` or `AWS Systems Manager Parameter Store` into ECS Task Definitions. RSA keys can be mounted as temporary volumes or injected as base64 environment strings (requires Spring Boot custom property deciphering).
* **GCP:** Use `Google Secret Manager`.
* **Kubernetes:** Define `Secret` manifests, and inject them as environment variables via `envFrom`:

```yaml
envFrom:
  - secretRef:
      name: authkit-production-secrets
volumeMounts:
  - name: jwt-keys
    mountPath: "/etc/authkit/keys"
    readOnly: true
```

## 3. Horizontal Scalability and State

* **Statelessness:** Security tokens are stateless JWTs validated dynamically. There is no active session `HttpSession` replicating across instances.
* **Distributed Caching:** Rate limiting, endpoint abuse throttles, refresh-token state, OAuth token revocation, and one-time MFA login challenges rely on centralized **Redis with authentication enabled**. Refresh-token family pointers are stored separately from per-user session hashes so reuse detection is O(1) and does not scan all user sessions. Per-request authority snapshots and MFA-enabled status use deliberately short local Caffeine caches; reduce `AUTH_AUTHORITY_CACHE_TTL_SECONDS` or `AUTH_MFA_STATUS_CACHE_TTL_SECONDS` if revocation freshness requirements are stricter. If Redis is unavailable, high-risk abuse throttles and lockout degrade to stricter per-node local enforcement and emit critical metrics; token storage flows do not have a safe local substitute.
* **Database Concurrency:** All migrations run via Flyway at application startup. Tune Hikari pool limits per replica so total connections stay below PostgreSQL capacity. JDBC batching is enabled for small write bursts such as MFA backup-code generation.
* **Email Delivery:** Registration, recovery, and password-change emails are first written into the transactional `email_outbox` table. In `queue` mode, the dedicated email scheduler publishes due rows to RabbitMQ after commit and marks them `QUEUED`; the Rabbit listener marks them `SENT` only after the configured provider returns acceptance and a provider message id. Queue publish failures, provider failures, and delivery-ack timeouts are retried with backoff, and poison messages can dead-letter to `authkit.email.dlq`, so RabbitMQ latency does not hold user database transactions open. In `direct` mode, the scheduler claims only `AUTH_EMAIL_OUTBOX_DIRECT_BATCH_SIZE` rows, marks each row `QUEUED` as external delivery in-flight, and submits provider calls to the bounded direct dispatch worker pool; worker success marks `SENT` and worker failure marks `FAILED`. RabbitMQ credentials and Rabbit health/metrics artifacts are not required in this mode.
* **Durable Security Events:** Authentication and account lifecycle flows enqueue privacy-safe rows to `security_events` through a bounded writer. Events store masked identifiers and keyed HMAC identifiers, never raw passwords, tokens, or request bodies. If the writer queue saturates and `AUTH_AUDIT_SYNC_ON_OVERLOAD=true`, events fall back to synchronous persistence to preserve forensic coverage under load.
* **MFA Baseline:** TOTP enrollment requires current-password step-up, stores encrypted secrets in versioned AES-GCM envelopes with PBKDF2-derived keys and key IDs, and returns raw setup material only during enrollment. Enabling or disabling TOTP revokes refresh sessions. Backup codes are generated once, stored only as keyed hashes, consumed atomically, and audited on use. Password change, account export, account deletion, logout-all, individual session revocation, MFA disablement, and backup-code regeneration require MFA proof when MFA is enabled for the account. Regular profile reads/updates and session listing do not require MFA to avoid unnecessary user friction.
* **Passkeys/WebAuthn:** WebAuthn registration and assertion are verified by Yubico `webauthn-server-core` with authenticator user verification required. Configure `AUTH_PASSKEY_RP_ID` and `AUTH_PASSKEY_ORIGINS` to exactly match production browser origins before enabling passkeys. Production startup rejects `AUTH_PASSKEY_ALLOW_ORIGIN_PORT=true`. Registration and disablement require current-password step-up and, when enrolled, MFA proof. AuthKit stores credential IDs, COSE public keys, signature counters, transports, discoverability, and timestamps; private key material never leaves the authenticator. For administrators, passkeys should be the preferred MFA method; TOTP remains a supported fallback but is not phishing resistant.
* **OAuth2/OIDC Provider:** AuthKit implements the provider role for authorization-code + PKCE. Client applications are created through `/api/v1/admin/oauth-clients`; confidential client secrets are returned once at creation or rotation and stored only with the configured slow password hash. Authorization requires explicit user consent unless an active `oauth_consents` row already covers the requested client scopes. Authorization codes are stored as SHA-256 hashes, consumed atomically, and exchanged for RS256 access/ID tokens published through JWKS. Revocation, introspection, userinfo, complete discovery metadata, and client-scoped throttles are implemented. Social-login relying-party federation is not enabled by default and should be introduced as a separate provider-linking design if required.
* **JWT Key Rotation:** `AUTH_JWT_KEY_ID` identifies the active signing key. During planned rotation, publish old public keys through `AUTH_JWT_RETIRING_PUBLIC_KEYS` until every token signed by the old key has expired, then remove them. During emergency compromise, add the compromised key id to `AUTH_JWT_REVOKED_KEY_IDS`, roll the active private key, restart pods, and force downstream JWKS refresh. Downstream services must validate issuer, audience, expiry, algorithm, `kid`, tenant, and scopes/authorities.
* **Password Recovery and Password Policy:** Password reset email links place the recovery token in the URL fragment, not in a query string, and the API consumes reset tokens from the request body. AuthKit sends `Referrer-Policy: no-referrer`, consumes recovery tokens atomically, enforces short TTL/one-time use, rejects weak/common/identity-derived/reused passwords, and records password history.
* **Admin and Policy Plane:** `/api/v1/admin/**` requires `ROLE_ADMIN` from a live authority snapshot. The path is not treated as a secret; security comes from server-side RBAC, MFA step-up on writes, last-admin demotion protection, rate limits, audit events, and network controls.
* **Incident Metrics:** Prometheus metrics include `security_login_failed_total`, `security_account_locked_total`, `security_password_reset_failed_total`, `security_refresh_token_reuse_total`, `security_mfa_challenge_failed_total`, `security_mfa_login_failed_total`, `security_mfa_step_up_failed_total`, `security_mfa_backup_code_used_total`, `rate_limit_dropped_total`, `security_abuse_control_blocked_total`, `security_abuse_control_degraded_total`, `security_lockout_degraded_total`, `security_events_overloaded_total`, `security_events_dropped_total`, and `security_infrastructure_failure_total`. The sample `k8s/06-prometheus-rules.yaml` alerts on abuse spikes, MFA failures, MFA login/step-up failures, backup-code use, token reuse, event drops, rate-limit drops, degraded abuse controls, degraded lockout, and infrastructure failures. `/actuator/prometheus` requires a trusted source network plus the internal worker token via `X-Worker-Token`; configure Prometheus, an in-cluster scrape proxy, or the ingress controller to inject that header only from the monitoring namespace.
* **Data Governance:** Account export is available at `POST /api/v1/users/me/export` with the current password as step-up proof, plus `mfaCode` when MFA is enabled. Consent snapshot is available at `GET /api/v1/users/me/consent`, and account deletion/anonymization is available at `DELETE /api/v1/users/me` with the same password-plus-MFA-if-enabled step-up. Registration records append-only consent history in `consent_events`; OAuth authorization consent is stored in `oauth_consents`; exports include the current consent snapshot, historical consent events, OAuth client consents, and bounded security events. Deletion immediately anonymizes direct PII, evicts the per-user authority cache, then revokes refresh sessions and emits lifecycle events after the database commit. Retention purges expired security events, deleted-account tombstones, passkey challenges, and OAuth authorization codes in bounded batches according to configured windows.
* **Registration Enumeration:** Public deployments must keep `AUTH_REGISTRATION_STEALTH_CONFLICTS=true`, which makes `/api/v1/auth/register` return a generic acknowledgement without exposing whether an email is already registered. Development and trusted internal integrations may disable it if they require explicit conflict responses.
* **Tenant Strategy:** AuthKit currently models one tenant identifier per user and emits only the canonical JWT claim `tenant_id`. Hibernate tenant filtering is enabled from authenticated service calls when a valid UUID tenant claim is present, and profile/session operations also perform object-level tenant checks. New tenant-owned tables must add equivalent service tests before production use.
* **CSRF:** Refresh and logout are cookie-backed, so clients must echo the readable CSRF cookie in the configured CSRF header. This is stateless double-submit protection and does not introduce server sessions.
* **CORS:** Application-level CORS must list explicit HTTPS origins. Production startup rejects missing origins, wildcard-with-credentials, and non-HTTPS origins. Keep CORS and gateway policy aligned so browser access is predictable.
* **Reverse Proxy:** Production traffic must terminate TLS before reaching AuthKit and forward `X-Forwarded-Proto`. The application uses forwarded headers so HSTS is emitted for HTTPS requests behind a proxy.
* **Image Pinning:** Production manifests should reference immutable image digests. The sample Kubernetes deployment uses a digest placeholder that must be replaced by the release artifact digest generated by the build pipeline.
* **NetworkPolicy HTTPS Egress:** The sample Kubernetes NetworkPolicy allows external HTTPS because standard NetworkPolicy cannot restrict by FQDN. Enforce provider-specific FQDN egress allow-lists at the gateway/firewall layer for Resend and image/security-update endpoints.

## 4. Prompt 2 Operational Runbooks

### Redis Abuse-Control or Lockout Degradation

Trigger: `AuthKitAbuseControlDegraded` or `AuthKitLockoutDegraded`.

Immediate response:
1. Confirm Redis cluster health, authentication, DNS, network policy, and client connection errors.
2. Treat public auth endpoints as under-restricted until distributed Redis enforcement is restored; keep WAF/ingress rate limits conservative during the incident.
3. Watch `security_abuse_control_blocked_total`, login failures, MFA failures, and password recovery volume for attack pressure.
4. After Redis recovers, verify the degraded metrics stop increasing and run a smoke test for login, refresh, recovery, and MFA login.

### JWT Signing-Key Rotation

Planned rotation:
1. Generate a new RSA key pair and set it as `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, and a new `AUTH_JWT_KEY_ID`.
2. Add the previous public key to `AUTH_JWT_RETIRING_PUBLIC_KEYS`.
3. Deploy all AuthKit pods, then keep the retiring key published longer than the maximum access-token lifetime plus downstream JWKS cache TTL.
4. Remove the retiring key once old tokens are guaranteed expired.

Emergency compromise:
1. Add the compromised `kid` to `AUTH_JWT_REVOKED_KEY_IDS`.
2. Rotate the active key pair and restart AuthKit pods.
3. Force downstream JWKS refresh or restart resource servers.
4. Revoke affected refresh sessions if token theft is suspected.

### Worker Token Rotation

1. Put the old token in `WORKER_PREVIOUS_TOKENS` and deploy AuthKit with the new `WORKER_TOKEN`.
2. Update Prometheus, scrape proxies, and internal workers to send the new token.
3. Confirm successful scrapes from trusted networks.
4. Remove the old token from `WORKER_PREVIOUS_TOKENS` after all clients are updated.

### Email Delivery Failure

Trigger: `security_infrastructure_failure_total{component="email_outbox"}` or `{component="email_provider"}`.

Response: inspect `email_outbox` rows in `FAILED` or, in `queue` mode, long-lived `QUEUED` state. For `queue` mode, check RabbitMQ queue/DLQ depth; for all provider-backed modes, confirm provider health and credential validity, then allow the outbox processor to retry. Do not manually mark rows `SENT` unless provider acceptance and `provider_message_id` are independently confirmed.

## 5. Build-Time Supply Chain Verification

The normal Maven `verify` lifecycle is deterministic and does not require live NVD access. CI runs the Java build/tests, generates a CycloneDX SBOM, runs pinned CodeQL Java SAST with `security-extended` and `security-and-quality` queries, and uses Trivy for filesystem dependency-manifest scanning plus container-image scanning.

OWASP Dependency-Check remains available as an explicit, NVD-backed security profile for release or scheduled security jobs. The plugin reads the key from `NVD_API_KEY` using `nvdApiKeyEnvironmentVariable`, which avoids exposing the secret in Maven debug logs. Its local vulnerability database is stored under `target/dependency-check-data` so verification is isolated from stale shared H2 locks.

Run locally with the key already exported in the shell:

```bash
export NVD_API_KEY=...
./mvnw -Pdependency-check verify
```

CI or release automation should inject `NVD_API_KEY` from its secret store for this explicit profile and should not print the value in logs. If NVD rejects the key or rate-limits unauthenticated traffic, the default build still remains healthy while the explicit vulnerability-gate job fails visibly.
