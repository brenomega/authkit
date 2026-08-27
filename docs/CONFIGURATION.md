# Configuration reference

[Português (Brasil)](CONFIGURATION-ptBR.md) | English is normative.

`deploy/golden/compose.yml`, `deploy/golden/.env.example`, `src/main/resources/application.yml`, and `application-prod.yml` are the machine-readable sources. This page defines operator meaning; secret values use mounted `*_FILE` variables supported by `docker/entrypoint.sh`.

| Area | Required golden settings | Contract |
| --- | --- | --- |
| Public identity | `AUTHKIT_PUBLIC_HOST`, `AUTH_JWT_ISSUER`, `AUTH_JWT_AUDIENCE`, `AUTH_JWT_KEY_ID` | Stable HTTPS issuer; explicit audience and key ID; RSA key files mounted read-only. |
| Database | `DB_*`, `SPRING_FLYWAY_*`, `AUTH_RETENTION_DB_*` | PostgreSQL 17; distinct owner/runtime/retention credentials. Runtime cannot mutate/delete audit rows. |
| Redis | `REDIS_*`, `AUTH_TOKEN_STORAGE_BACKEND=redis` | Redis 7 authenticated; required for the golden path and high-risk fail-closed behavior. |
| Browser | frontend URLs, exact `AUTH_CORS_ALLOWED_ORIGINS`, secure refresh cookie, CSRF | HTTPS origins only in production; no wildcards with credentials. |
| Tokens | `AUTH_ACCESS_TOKEN_TTL_SECONDS=300` | Recommended maximum five minutes; refresh tokens remain opaque, rotating, family-bound. |
| Registration/legal | mode, terms/privacy versions, lawful basis | `public` or `restricted` is explicit. Operator owns legal text and decisions. |
| Email | direct outbox, provider, sender, SMTP/Resend credentials, template directory | SMTP TLS is neutral default. Templates are mandatory external assets. |
| Password | `AUTH_PASSWORD_HIBP_ENABLED=true`, Argon2 concurrency | HIBP and bounded Argon2 are enabled on the golden path. |
| Passkeys | RP ID/name and exact origins | RP ID must match the deployment domain; origin ports are not accepted in production. |
| OAuth/social | authorization UI; social opt-in and provider admin records | Google/generic OIDC issuers are exact operator allowlist entries. Provider secrets are encrypted. |
| Proxy | trusted proxy CIDR, XFF enabled with depth 1, Spring forwarding disabled | Forwarded headers are accepted only from the fixed Caddy peer. |
| Audit/retention | audit HMAC pepper, retention job and restricted login | Critical audit failure aborts its mutation. Retention is bounded and separately authorized. |
| Internal introspection | `WORKER_TOKEN_FILE` plus trusted CIDRs | The worker credential is network-bound and rotatable; do not expose internal paths publicly. |

Production validation fails startup for placeholders, missing/weak secrets, HTTP public URLs, absent registration mode, unsafe CORS/proxy settings, non-TLS SMTP, missing templates, access TTL above 300 seconds, disabled HIBP, missing Redis, or missing retention separation. Secrets must never be supplied as CLI arguments or committed `.env` values.

Resend is selected with `AUTH_EMAIL_PROVIDER_TYPE=resend` and `RESEND_API_KEY_FILE`; SMTP is selected with `smtp`. RabbitMQ and JDBC token storage are unsupported previews and are excluded from production instructions.
