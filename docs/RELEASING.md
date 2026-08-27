# Release-candidate procedure

[Português (Brasil)](RELEASING-ptBR.md) | English is normative. The repository currently identifies an unpublished `0.1.0-rc.1` implementation candidate. A candidate build is evidence for audit; it is not authorization to tag, publish, promote, deploy, or accept risk.

## Candidate freeze

1. Record branch, HEAD, full working-tree status, and a patch checksum. If the tree is dirty, identify the evidence as a tree candidate and bind it to the recorded patch; do not imply that HEAD alone contains the changes.
2. Keep `revision`, `changelist`, `CHANGELOG.md`, the OpenAPI version, documentation, OCI labels, and evidence manifest coherent.
3. Run `testing/release/build-candidate-evidence.sh`. It performs the local clean build, full test suite, sample tests, JAR/context/image inspection, SBOM/checksums, and records tool availability without fabricating absent scan/signature results.
4. Run PostgreSQL 17 and Redis 7 integration tests, the documented golden fresh-install/bootstrap/manual flows, backup/restore, controlled failures, and the four-hour reference-host load/soak harness.
5. Execute blocking dependency, static-code, secret, IaC, container, and supply-chain scans against the exact candidate tree and image digest.
6. Produce an OCI manifest for both `linux/amd64` and `linux/arm64`, bind CycloneDX SBOMs and checksums to it, sign the immutable digest, and create verifiable SLSA-style provenance/attestation. Local preparation must not push or publish anything.
7. Re-evaluate all 16 gates in `docs/release/RELEASE_GATES.md`. Every unavailable external action remains `NOT PROVEN`, with the required credential/environment/operator action recorded.
8. Request a new independent audit. Only the maintainer may later authorize a final `0.1.0` version, tag, publication, promotion, or release.

CI is supporting evidence only when it ran against the same frozen commit/tree. Historical green runs, uploaded artifacts from another commit, mock providers, and a locally built mutable tag do not satisfy release gates.
