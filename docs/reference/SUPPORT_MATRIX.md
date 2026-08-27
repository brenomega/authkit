# Support matrix

[English](SUPPORT_MATRIX.md) | [Português (Brasil)](SUPPORT_MATRIX-ptBR.md)

English is normative. This matrix is version-bound to the v0.1.0 release candidate.

## Candidate golden path

The only release-gated target for v0.1 is one AuthKit OCI container on Linux with Java 21, PostgreSQL 17, authenticated Redis 7, direct durable outbox dispatch, SMTP over TLS or Resend, and a TLS reverse proxy. It is a single-instance greenfield deployment and does not promise high availability or live migration. This classification defines the candidate scope; it is not a production-readiness claim while release proof and final audit remain incomplete.

## Experimental and unsupported paths

| Capability | v0.1 classification | Default | Release instructions | Reason |
| --- | --- | --- | --- | --- |
| PostgreSQL/JDBC token storage without Redis | Unsupported preview | Off | Excluded | Code and unit coverage exist, but the required dedicated real-dependency smoke and operational proof are incomplete. |
| RabbitMQ dispatch | Unsupported preview | Off | Excluded | The adapter exists, but dedicated broker smoke, failure proof, and reproducible operator guidance are incomplete. |
| Kubernetes manifests | Unsupported example | Off | Excluded | Manifests are not a proven v0.1 production deployment path. |
| systemd deployment | Unsupported example | Off | Excluded | Units are reference material and have no complete v0.1 host proof. |
| Non-golden deployment tiers | Unsupported planning material | Off | Excluded | Capacity and operational claims have not been measured. |
| Gov.br federation | Unsupported | Off | Excluded | No implementation or real-provider proof is present. |
| Other database, Redis, OS, or platform versions | Unsupported | Off | Excluded | Only the versions in the golden path are release-gated. |

Unsupported preview code remains isolated behind explicit opt-in and must not weaken the golden defaults. Presence in the repository is not a support claim. A path may be promoted to experimental only after it has green unit and integration tests, a dedicated real-dependency smoke, reproducible configuration, documented limitations, and proof that disabled behavior does not affect GA defaults.
