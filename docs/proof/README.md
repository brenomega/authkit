# Candidate proof harnesses

[Português (Brasil)](README-ptBR.md) | English is normative.

The proof harnesses exercise the v0.1 golden path but never self-approve a release. Bind each report to HEAD, the tracked patch checksum, untracked-file manifest, candidate version, and immutable OCI digest. Do not record raw passwords, tokens, reset/action URLs, provider secrets, private keys, or full environment files.

Use `testing/release/build-candidate-evidence.sh` for the clean build, sample, artifact inspection, local image, SBOM/checksums and scanner inventory. Use `testing/proof/run-proof.sh` for functional smoke/negative/chaos orchestration and `testing/proof/run-reference-load.sh` for the mandatory four-hour reference-host run. The golden production proof uses only `docs/INSTALL.md`, not the development Compose files.

Every report records actual commands/results, hardware, non-secret configuration, provider acceptance separately from inbox observation, p50/p95/p99/errors/saturation/backlog, fault invariants, RPO/RTO, and alert routing. A missing tool, credential, public DNS/TLS environment, provider account, signing identity, or independent operator remains `NOT PROVEN` with the exact dependency named in `docs/release/RELEASE_GATES.md`.

The report template is `templates/proof-report-template.md`. Historical local reports are not current-candidate evidence and are intentionally not retained in the public tree.
