# AuthKit

AuthKit is a Spring Boot authentication service with first-party sessions, OAuth/OIDC, MFA, passkeys, tenant-aware authorization, durable email delivery, and security audit trails.

## Documentation

- [API contract](docs/openapi.yaml)
- [Integrator guide](docs/INTEGRATOR.md)
- [Deployment guide](DEPLOYMENT.md)
- [Deployment modes](docs/DEPLOYMENT_MODES.md)
- [Deployment tiers](docs/DEPLOYMENT_TIERS.md)
- [Module registry](docs/MODULES.md)
- [Cost model](docs/strategy/authkit-cost-model.md)
- [Proof, automation, and integration scaffolding plan](docs/strategy/authkit-proof-automation-integration-scaffolding.md)
- [Proof automation implementation plan](docs/strategy/authkit-proof-automation-implementation-plan.md)
- [Contract fixtures](testing/proof/fixtures/README.md)
- [Proof pack](docs/proof/README.md)
- [Go/no-go criteria](docs/proof/go-no-go-criteria.md)
- [Performance baselines](docs/proof/performance-baselines.md)
- [Remaining unproven proof items](docs/proof/unproven-items.md)
- [Deployment runbooks](docs/runbooks/README.md)
- [Spring resource-server sample](samples/resource-server-spring/README.md)
- [Browser session flow sample](samples/browser-session-flow/README.md)
- [Wavern integration spec](docs/integration/wavern-auth-integration-spec.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Use-case flows](docs/architecture/SYSTEM_USE_CASE_FLOWS.md)
- [Release process](docs/RELEASING.md)

Development builds use `0.1.0-SNAPSHOT`. Run the H2 suite with `./mvnw clean test -Dspring.profiles.active=test`.
