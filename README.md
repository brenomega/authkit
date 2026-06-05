# AuthKit

AuthKit is a Spring Boot authentication service with first-party sessions, OAuth/OIDC, MFA, passkeys, tenant-aware authorization, durable email delivery, and security audit trails.

## Documentation

- [API contract](docs/openapi.yaml)
- [Integrator guide](INTEGRATOR.md)
- [Deployment guide](DEPLOYMENT.md)
- [Deployment modes](docs/DEPLOYMENT_MODES.md)
- [Security model](SECURITY_MODEL.md)
- [Use-case flows](SYSTEM_USE_CASE_FLOWS.md)
- [Production audit](final_audit.md)
- [Release process](docs/RELEASING.md)

Development builds use `0.1.0-SNAPSHOT`. Run the H2 suite with `./mvnw clean test -Dspring.profiles.active=test`.
