# AuthKit

[Português (Brasil)](README-ptBR.md)

AuthKit is a headless, standalone authentication and identity service for greenfield SaaS applications. It provides first-party sessions, MFA and passkeys, Google and allowlisted generic OIDC federation, and an OAuth 2.0/OIDC authorization server.

AuthKit v0.1 targets greenfield initial SaaS launches through the documented golden path. It is not a live authentication migration product and makes no unmeasured scale or availability claim. The current working tree is an unpublished release candidate under implementation audit; production readiness has not been established and no deployment or publication is authorized before every mandatory gate passes.

## v0.1 golden path

The supported topology is one AuthKit OCI container on Linux with Java 21, PostgreSQL 17, authenticated Redis 7, direct durable email outbox dispatch, SMTP with required TLS or Resend, and a TLS reverse proxy. This is a single-instance topology; high availability, zero-downtime migration from another identity system, organization tenancy, and unmeasured capacity are outside the v0.1 contract.

Start with the [golden-path installation](docs/INSTALL.md), then use the [configuration reference](docs/CONFIGURATION.md), [email-template contract](docs/EMAIL_TEMPLATES.md), [security model](docs/SECURITY_MODEL.md), [operations guide](docs/OPERATIONS.md), and [OpenAPI contract](docs/openapi.yaml). The [support matrix](docs/reference/SUPPORT_MATRIX.md) is explicit about unsupported preview paths; [requirement traceability](docs/TRACEABILITY.md) and the [16 release gates](docs/release/RELEASE_GATES.md) state what is implemented and what remains unproven.

## Security boundaries

- `tenant_id` is an opaque one-person partition, never an organization or host-product authorization model.
- Roles are only `USER` and `PLATFORM_ADMIN`.
- First-party access, OAuth access, and ID tokens are separate classes and require explicit `token_use`.
- Refresh credentials and ceremony state are server-side, rotating or one-time, and immediately revocable inside AuthKit.
- Email HTML, localization, and branding belong to the integrating operator. AuthKit only validates, safely renders, queues, and records provider acceptance.
- OAuth/OIDC implements Authorization Code with PKCE S256. Implicit, password, client credentials, device, PAR, JAR, CIBA, and dynamic registration are not implemented.

## Development

Java 21 and Docker are required for the complete suite:

```sh
./mvnw clean verify
```

Tests that prove PostgreSQL and Redis semantics use Testcontainers. Production artifacts must also pass `testing/release/inspect-release-artifacts.sh`; test profiles and private test keys must never occur in the JAR, image, or build context.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [SUPPORT.md](SUPPORT.md), and [LICENSE](LICENSE). Contributions use DCO and Apache-2.0; no CLA is currently required.
