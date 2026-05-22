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
* `AUTH_ACCESS_TOKEN_TTL_SECONDS`: Access token lifetime in seconds. Default: `900`.
* `AUTH_REFRESH_TOKEN_TTL_DAYS`: Refresh-token-backed session lifetime in days. Default: `7`.
* `AUTH_RECOVERY_TOKEN_TTL_MINUTES`: Password recovery token lifetime in minutes. Default: `15`.
* `AUTH_REFRESH_COOKIE_NAME`: Refresh cookie name. Default: `Refresh-Token`.
* `AUTH_REFRESH_COOKIE_PATH`: Refresh cookie path scope. Default: `/api/v1/auth`.
* `AUTH_REFRESH_COOKIE_HTTP_ONLY`: Whether the refresh cookie is `HttpOnly`. Production should keep this `true`.
* `AUTH_REFRESH_COOKIE_SECURE`: Whether the refresh cookie requires HTTPS. Production should keep this `true`.
* `AUTH_REFRESH_COOKIE_SAME_SITE`: SameSite policy for refresh cookies. Default: `Strict`.

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
AUTH_ACCESS_TOKEN_TTL_SECONDS=900
AUTH_REFRESH_TOKEN_TTL_DAYS=7
AUTH_RECOVERY_TOKEN_TTL_MINUTES=15
AUTH_REFRESH_COOKIE_NAME=Refresh-Token
AUTH_REFRESH_COOKIE_PATH=/api/v1/auth
AUTH_REFRESH_COOKIE_HTTP_ONLY=true
AUTH_REFRESH_COOKIE_SECURE=true
AUTH_REFRESH_COOKIE_SAME_SITE=Strict
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
* **Distributed Caching:** Caching (when implemented) and Rate Limiting rely on a centralized **Redis** server. Multiple AuthKit app containers will coordinate seamlessly.
* **Database Concurrency:** All migrations run via Flyway at application startup. Concurrency limits should be monitored per instance, ensuring max pool limits do not overwhelm PostgreSQL.
* **Asynchronous Jobs:** Heavy background tasks (like external API calls to Resend) are managed by RabbitMQ. You can scale the RabbitMQ worker nodes dynamically via AMQP without hindering API request threads.
