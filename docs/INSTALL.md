# Golden-path installation

[Português (Brasil)](INSTALL-ptBR.md) | English is normative.

This procedure installs the supported single-instance v0.1 topology: AuthKit, PostgreSQL 17, authenticated Redis 7.4, and Caddy terminating TLS. Use a clean Linux host with Docker Engine and Compose v2, DNS for the public host, a valid TLS certificate, an SMTP account that requires TLS, and operator-authored email templates. Do not expose PostgreSQL, Redis, or AuthKit port 8080.

## 1. Prepare configuration

Copy `deploy/golden/.env.example` to `deploy/golden/.env` and replace every example value. Origins are exact HTTPS origins without wildcards. The issuer is derived from `AUTHKIT_PUBLIC_HOST` and must remain stable. Keep registration `restricted` until public signup is an intentional operator decision.

Create the directory selected by `AUTHKIT_SECRETS_DIRECTORY`. Follow `deploy/golden/secrets/README.md`; for local Compose use directory mode `0700` and read-only secret files mode `0444`, independent random values, an RSA signing pair of at least 2048 bits, and a certificate covering the public host. Never reuse the Flyway owner password as the runtime or retention password. `email_provider_credential` is the SMTP password by default; when `AUTHKIT_EMAIL_PROVIDER_TYPE=resend`, it is instead the Resend API key and the SMTP host/user values may be empty.

Create the 14 files required by [the email-template contract](EMAIL_TEMPLATES.md) in the absolute directory selected by `AUTHKIT_EMAIL_TEMPLATES_DIRECTORY`. AuthKit deliberately ships no production copy, localization, HTML, or branding.

Validate before starting:

```sh
docker compose --env-file deploy/golden/.env -f deploy/golden/compose.yml config -q
```

## 2. Build and start

Until an independently audited image digest exists, build locally from the reviewed tree:

```sh
docker compose --env-file deploy/golden/.env -f deploy/golden/compose.yml build authkit
docker compose --env-file deploy/golden/.env -f deploy/golden/compose.yml up -d
docker compose --env-file deploy/golden/.env -f deploy/golden/compose.yml ps
```

The first database initialization creates separate owner, runtime, and retention logins. Flyway applies migrations as the owner; normal requests use `authkit_app`; retention can delete audit data only through scoped audited functions.

Verify through TLS, never by bypassing Caddy:

```sh
curl --fail --silent --show-error https://AUTHKIT_PUBLIC_HOST/actuator/health
curl --fail --silent --show-error https://AUTHKIT_PUBLIC_HOST/.well-known/openid-configuration
```

## 3. Bootstrap the first administrator

Create a temporary local JSON document with mode `0600`; unlike container-mounted service secrets, this stays on the operator host and is read through stdin. It is a secret because it contains the initial password:

```json
{
  "email": "admin@example.com",
  "password": "replace-with-a-unique-strong-password",
  "name": "Initial Administrator",
  "termsAccepted": true,
  "privacyPolicyAccepted": true
}
```

Pass it on stdin, not as an argument:

```sh
docker compose --env-file deploy/golden/.env -f deploy/golden/compose.yml run --rm -T authkit bootstrap-admin < /secure/local/bootstrap-admin.json
```

The command is non-HTTP, locks a singleton database guard, creates one verified `PLATFORM_ADMIN`, records a synchronous critical audit event, and rejects repeats. Delete the local input through the host's recoverable secret-disposal process. Log in and enroll TOTP or a passkey immediately; administrative mutations remain blocked until a local second factor exists and each mutation has recent password plus TOTP step-up or fresh passkey authentication.

## 4. Acceptance checklist

- TLS certificate and hostname validation succeed; direct backend ports are unreachable externally.
- Registration mode, terms/privacy versions, exact CORS origins, passkey RP, issuer, audience, and authorization UI are operator-approved.
- SMTP STARTTLS is both enabled and required; a real provider acceptance ID and separate inbox observation are recorded. `ACCEPTED` never means inbox delivery.
- A registration/confirmation/login/refresh/logout flow succeeds; confirmation and old refresh credentials fail on replay.
- PostgreSQL and Redis backups are encrypted and stored off-host; a clean-host restore drill is completed before launch.
- Alert routing, retention credentials, worker token, signing-key rotation, provider failure, Redis fail-closed behavior, and rollback procedures are exercised using [the operations guide](OPERATIONS.md).

Stopping with `docker compose down` preserves named database, Redis, and Caddy volumes. `down -v` destroys data and is not part of routine operation.
