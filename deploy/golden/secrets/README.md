# Secret file contract

Create the secret directory with mode `0700` and the files with mode `0444`;
never commit their contents. Docker Compose implements local secrets as
read-only bind mounts, so the non-root AuthKit, Redis, and Caddy processes must
be able to read the mounted inode. The parent directory prevents other host
users from traversing to those files. On an orchestrator with native secrets,
use its non-root UID/GID and narrower file mode instead.

`postgres_owner_password`, `postgres_app_password`, `postgres_retention_password`,
`redis_password`, `jwt_public.pem`, `jwt_private.pem`, `audit_hash_pepper`,
`mfa_encryption_key`, `worker_token`, `email_provider_credential`, `tls_certificate.pem`, and
`tls_private_key.pem`.

Use independent, randomly generated values for every password/token. The JWT
pair must be RSA (at least 2048 bits). The TLS certificate must cover
`AUTHKIT_PUBLIC_HOST`. The owner credential is used only by Flyway; application
queries run as `authkit_app`, while audit retention runs as
`authkit_retention_worker` through its restricted database functions.

`email_provider_credential` contains the SMTP password when
`AUTHKIT_EMAIL_PROVIDER_TYPE=smtp`, or the Resend API key when it is `resend`.
Only the selected provider consumes it. Never place both credentials in one
file; use a fresh secret when switching providers.
