# Releasing

Development builds retain the default `-SNAPSHOT` changelist. Before a release:

1. Update `revision`, `CHANGELOG.md`, and `docs/openapi.yaml` together.
2. Run `./mvnw clean verify -Dspring.profiles.active=test -Dchangelist=` and the Docker-backed PostgreSQL migration job.
3. Publish only immutable artifacts produced by that verified commit. Create the tag after the build succeeds; resume development by advancing `revision` and restoring the default changelist.

CI publishes CycloneDX JSON and XML SBOMs for each verified build. Image signing and release promotion attestations remain Prompt 3 work.
