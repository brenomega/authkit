#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

export SPRING_PROFILES_ACTIVE=dev
export SERVER_PORT=18080
export LOGGING_LEVEL_ROOT=INFO
export LOGGING_LEVEL_ORG_SPRINGFRAMEWORK_CORE_ENV=INFO
export DB_URL=jdbc:postgresql://127.0.0.1:15432/authkit
export DB_USERNAME=authkit
export DB_PASSWORD=local-proof-postgres-password
export REDIS_HOST=127.0.0.1
export REDIS_PORT=16379
export REDIS_PASSWORD=local-proof-redis-password
export JWT_PUBLIC_KEY=file:src/test/resources/test-keys/app.pub
export JWT_PRIVATE_KEY=file:src/test/resources/test-keys/app.key
export AUTH_JWT_ISSUER=http://127.0.0.1:18080
export AUTH_JWT_AUDIENCE=authkit-manual-api
export AUTH_JWT_KEY_ID=manual-proof-key
export AUTH_FRONTEND_ACTIVATION_URL=http://127.0.0.1:3000/activate
export AUTH_FRONTEND_PASSWORD_RESET_URL=http://127.0.0.1:3000/reset-password
export AUTH_FRONTEND_EMAIL_CHANGE_URL=http://127.0.0.1:3000/change-email
export AUTH_REGISTRATION_MODE=public
export AUTH_EMAIL_OUTBOX_DISPATCH_MODE=direct
export AUTH_EMAIL_PROVIDER_TYPE=smtp
export AUTH_EMAIL_PROVIDER_FROM='AuthKit Manual <authkit@example.test>'
export AUTH_EMAIL_SMTP_HOST=127.0.0.1
export AUTH_EMAIL_SMTP_PORT=11025
export AUTH_EMAIL_SMTP_AUTH=false
export AUTH_EMAIL_SMTP_STARTTLS_ENABLED=false
export AUTH_EMAIL_SMTP_STARTTLS_REQUIRED=false
export AUTH_EMAIL_TEMPLATE_DIRECTORY=src/test/resources/email-templates
export AUTH_TOKEN_STORAGE_BACKEND=redis
export AUTH_TOKEN_STORAGE_SINGLE_INSTANCE_MODE=false
export AUTH_RETENTION_JOB_ENABLED=false
export AUTH_PASSWORD_HIBP_ENABLED=false
export AUTH_ABUSE_FAIL_CLOSED_HIGH_RISK=true
export AUTH_CORS_ALLOWED_ORIGINS=http://127.0.0.1:3000
export AUTH_PASSKEY_RP_ID=127.0.0.1
export AUTH_PASSKEY_ORIGINS=http://127.0.0.1:3000
export AUTH_PASSKEY_ALLOW_ORIGIN_PORT=true
export AUTH_TERMS_VERSION=manual-v1
export AUTH_PRIVACY_POLICY_VERSION=manual-v1
export AUTH_AUDIT_HASH_PEPPER=local-manual-audit-hash-pepper-at-least-32-bytes
export AUTH_MFA_SECRET_ENCRYPTION_KEY=local-manual-mfa-encryption-key-at-least-32-bytes
export AUTH_MFA_SECRET_ENCRYPTION_KEY_ID=manual-mfa-key
export AUTH_MFA_SECRET_ENCRYPTION_KDF_ITERATIONS=1000
export WORKER_TOKEN=local-manual-worker-token
export NETWORK_SECURITY_TRUSTED_ORIGINS=127.0.0.1/32
export NETWORK_STRATEGY_CLOUDFLARE_ENABLED=false
export NETWORK_STRATEGY_X_FORWARDED_FOR_ENABLED=false

exec ./mvnw spring-boot:run
