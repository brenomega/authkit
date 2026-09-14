# Local golden-path proof overlay

This test-only overlay adds Mailpit with mandatory STARTTLS and `--ignore-duplicate-ids` to the production golden Compose. Mailpit therefore rejects repeat storage by AuthKit's stable RFC 5322 `Message-ID`, and the overlay explicitly enables the production relay-deduplication assertion. It does not weaken the AuthKit `prod` profile, TLS proxy, mounted-secret, database-role, Redis, HIBP, or email-template configuration.

Start from the production preparation in [`docs/INSTALL.md`](../../docs/INSTALL.md): copy `deploy/golden/.env.example` to the ignored `deploy/golden/.env`, create every secret listed in `deploy/golden/secrets/README.md`, and provide all 14 operator email-template files. For this local proof only, the non-production fixtures in `src/test/resources/email-templates` may be used as `AUTHKIT_EMAIL_TEMPLATES_DIRECTORY`; they are never copied into the release image. Set both `AUTHKIT_SECRETS_DIRECTORY` and `AUTHKIT_PROOF_SECRETS_DIRECTORY` to the proof secret directory, choose an unused localhost `AUTHKIT_HTTPS_PORT` and `AUTHKIT_PROOF_MAILPIT_PORT`, and set `AUTHKIT_PUBLIC_HOST` to the hostname used in the certificate below.

The certificate mounted as `tls_certificate` is reused by Mailpit in this local-only overlay. It must therefore contain both the public proof hostname and `DNS:mailpit` in Subject Alternative Name. A certificate for only the public hostname fails SMTP hostname verification with `No subject alternative DNS name matching mailpit found`. From an empty proof-secret directory, generate a local certificate with both names (replace the example host before running):

```sh
export AUTHKIT_PUBLIC_HOST=authkit.local.test
mkdir -p /secure/local-proof/secrets
openssl req -x509 -newkey rsa:3072 -nodes -days 2 \
  -subj "/CN=${AUTHKIT_PUBLIC_HOST}" \
  -addext "subjectAltName=DNS:${AUTHKIT_PUBLIC_HOST},DNS:mailpit" \
  -keyout /secure/local-proof/secrets/tls_private_key.pem \
  -out /secure/local-proof/secrets/tls_certificate.pem
cp /secure/local-proof/secrets/tls_certificate.pem /secure/local-proof/ca.pem
openssl x509 -in /secure/local-proof/secrets/tls_certificate.pem -noout -ext subjectAltName
```

The last command must print both DNS names. Build the mounted trust store from the candidate JVM's public CA set plus this generated local Mailpit CA; a local-CA-only trust store would break outbound HTTPS such as HIBP:

```sh
testing/golden/prepare-smtp-truststore.sh \
  /secure/local-proof/ca.pem \
  /secure/local-proof/secrets/smtp-truststore.p12
```

Validate and start the overlay from the repository root:

```sh
docker compose --env-file deploy/golden/.env \
  -f deploy/golden/compose.yml \
  -f testing/golden/compose.local-proof.yml config --quiet
docker compose --env-file deploy/golden/.env \
  -f deploy/golden/compose.yml \
  -f testing/golden/compose.local-proof.yml up -d
```

Acceptance requires a healthy stack, successful HTTPS hostname validation, a registration or recovery request, one Mailpit message, and an AuthKit `email_outbox` row in `ACCEPTED`. The SMTP crash/reclaim drill must then preserve that row's stable `Message-ID`, force the same outbox item through stale-claim recovery, and prove Mailpit still stores exactly one message. Stop the proof with the same file list and `down`; add `-v` only when intentionally destroying the proof data.

Mailpit proves local SMTP protocol acceptance and deterministic duplicate suppression only. It is not evidence for an external SMTP provider, Resend, inbox delivery, spam placement, public TLS, or either browser topology. Never use this overlay in production or report it as Gate 3/4 proof.
