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
* `RABBIT_HOST`: Hostname of the RabbitMQ cluster
* `RABBIT_PORT`: AMQP Port (typically `5672`)
* `RABBIT_USERNAME`: Broker username
* `RABBIT_PASSWORD`: Broker password

#### Redis (Caching & Rate Limiting)
* `REDIS_HOST`: Hostname of the Redis server
* `REDIS_PORT`: Redis port (typically `6379`)

#### Security & Authentication
* `JWT_PUBLIC_KEY`: The absolute path to the RSA Public Key (`.pub` or `.pem`). This file must be mounted securely into the container.
* `JWT_PRIVATE_KEY`: The absolute path to the RSA Private Key (`.key` or `.pem`). This file must be mounted securely into the container.
* `AUTH_JWT_ISSUER`: Expected JWT issuer value. Must match the issuer used by downstream services validating AuthKit access tokens.
* `AUTH_JWT_AUDIENCE`: Expected JWT audience value. Downstream services should reject tokens not issued for this audience.
* `AUTH_JWT_KEY_ID`: Public key identifier published in JWKS and embedded in issued JWT headers.
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
* `AUTH_EMAIL_OUTBOX_ENABLED`: Enables the durable email outbox dispatcher. Default: `true`.
* `AUTH_EMAIL_OUTBOX_BATCH_SIZE`: Maximum email outbox messages claimed per poll. Default: `50`.
* `AUTH_EMAIL_OUTBOX_POLL_DELAY_MS`: Dispatcher polling interval. Default: `5000`.
* `AUTH_EMAIL_OUTBOX_LOCK_TTL_SECONDS`: Time before an abandoned `PROCESSING` email is eligible for retry. Default: `300`.
* `AUTH_TERMS_VERSION`: Current Terms of Use version recorded at registration.
* `AUTH_PRIVACY_POLICY_VERSION`: Current Privacy Policy version recorded at registration.
* `AUTH_LAWFUL_BASIS`: Lawful basis for account data processing. Allowed values include `consent`, `contract`, `legal_obligation`, `vital_interests`, `public_task`, and `legitimate_interests`.
* `AUTH_SECURITY_EVENT_RETENTION_DAYS`: Retention window for durable security events. Default: `365`.
* `AUTH_DELETED_ACCOUNT_RETENTION_DAYS`: Retention window for deleted account tombstones/anonymized records. Default: `0`.
* `AUTH_DATA_EXPORT_SECURITY_EVENT_LIMIT`: Maximum durable security events included in a user data export. Default: `100`.
* `AUTH_RETENTION_JOB_ENABLED`: Enables scheduled security-event retention cleanup. Default: `true`.
* `AUTH_RETENTION_JOB_CRON`: Cron expression for retention cleanup. Default: `0 30 3 * * *`.

#### External Integrations
* `RESEND_API_KEY`: API Token for the Resend email service.
* `AUTH_FRONTEND_ACTIVATION_URL`: Public frontend activation URL, without query string.
* `AUTH_FRONTEND_PASSWORD_RESET_URL`: Public frontend password reset URL, without query string.

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
JWT_PUBLIC_KEY=file:/etc/authkit/keys/app.pub
JWT_PRIVATE_KEY=file:/etc/authkit/keys/app.key
AUTH_JWT_ISSUER=https://auth.example.com
AUTH_JWT_AUDIENCE=https://api.example.com
AUTH_JWT_KEY_ID=authkit-prod-key-1
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
AUTH_EMAIL_OUTBOX_ENABLED=true
AUTH_EMAIL_OUTBOX_BATCH_SIZE=50
AUTH_EMAIL_OUTBOX_POLL_DELAY_MS=5000
AUTH_EMAIL_OUTBOX_LOCK_TTL_SECONDS=300
AUTH_TERMS_VERSION=terms-v1
AUTH_PRIVACY_POLICY_VERSION=privacy-v1
AUTH_LAWFUL_BASIS=consent
AUTH_SECURITY_EVENT_RETENTION_DAYS=365
AUTH_DELETED_ACCOUNT_RETENTION_DAYS=0
AUTH_DATA_EXPORT_SECURITY_EVENT_LIMIT=100
AUTH_RETENTION_JOB_ENABLED=true
AUTH_RETENTION_JOB_CRON="0 30 3 * * *"
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
* **Distributed Caching:** Rate limiting and refresh-token state rely on centralized **Redis**. Per-request authority snapshots use a deliberately short local Caffeine cache; reduce `AUTH_AUTHORITY_CACHE_TTL_SECONDS` if revocation latency requirements are stricter.
* **Database Concurrency:** All migrations run via Flyway at application startup. Concurrency limits should be monitored per instance, ensuring max pool limits do not overwhelm PostgreSQL.
* **Email Delivery:** Registration, recovery, and password-change emails are first written into the transactional `email_outbox` table. The scheduler publishes due rows to RabbitMQ after commit and retries failed messages with backoff, so RabbitMQ latency does not hold user database transactions open.
* **Durable Security Events:** Authentication and account lifecycle flows write privacy-safe rows to `security_events` in independent transactions. Events store masked and hashed identifiers, never raw passwords, tokens, or request bodies.
* **Incident Metrics:** Prometheus metrics include `security_login_failed_total`, `security_account_locked_total`, `security_password_reset_failed_total`, `security_refresh_token_reuse_total`, `rate_limit_dropped_total`, and `security_infrastructure_failure_total`. The sample `k8s/06-prometheus-rules.yaml` alerts on abuse spikes, token reuse, rate-limit drops, and infrastructure failures.
* **Data Governance:** Account export is available at `GET /api/v1/users/me/export`, consent snapshot at `GET /api/v1/users/me/consent`, and account deletion/anonymization at `DELETE /api/v1/users/me`. Deletion revokes refresh sessions and immediately anonymizes direct PII while preserving audit-minimal lifecycle evidence.
* **Registration Enumeration:** Public deployments must keep `AUTH_REGISTRATION_STEALTH_CONFLICTS=true`, which makes `/api/v1/auth/register` return a generic acknowledgement without exposing whether an email is already registered. Development and trusted internal integrations may disable it if they require explicit conflict responses.
* **Tenant Strategy:** AuthKit currently models one tenant identifier per user and emits only the canonical JWT claim `tenant_id`. Hibernate tenant filtering is enabled from authenticated service calls when a valid UUID tenant claim is present, and profile/session operations also perform object-level tenant checks. New tenant-owned tables must add equivalent service tests before production use.
* **CSRF:** Refresh and logout are cookie-backed, so clients must echo the readable CSRF cookie in the configured CSRF header. This is stateless double-submit protection and does not introduce server sessions.
* **Reverse Proxy:** Production traffic must terminate TLS before reaching AuthKit and forward `X-Forwarded-Proto`. The application uses forwarded headers so HSTS is emitted for HTTPS requests behind a proxy.
* **Image Pinning:** Production manifests should reference immutable image digests. The sample Kubernetes deployment uses a digest placeholder that must be replaced by the release artifact digest generated by the build pipeline.
* **NetworkPolicy HTTPS Egress:** The sample Kubernetes NetworkPolicy allows external HTTPS because standard NetworkPolicy cannot restrict by FQDN. Enforce provider-specific FQDN egress allow-lists at the gateway/firewall layer for Resend and image/security-update endpoints.
