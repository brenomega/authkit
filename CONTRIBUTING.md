# Contributing to AuthKit

AuthKit welcomes focused bug fixes, tests, documentation, and security hardening. Discuss large behavioral or public-contract changes in an issue before investing substantial work. Never put credentials, private keys, personal data, or undisclosed vulnerabilities in a public contribution.

## Development workflow

1. Fork the repository and create a focused branch.
2. Use Java 21 and run `./mvnw clean verify -Dspring.profiles.active=test -B`.
3. Run `./mvnw -f samples/resource-server-spring/pom.xml test -B` when token validation changes.
4. Run `git diff --check` and the relevant proof or migration tests.
5. Update English normative documentation and its pt-BR translation together when the public contract changes.
6. Open a pull request explaining the risk, compatibility impact, tests, and evidence.

Tests must not be removed, weakened, or replaced by mocks merely to make a change pass. Flyway migrations are forward-only. New dependencies require a license and supply-chain review.

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin 1.1](https://developercertificate.org/), without a CLA. Sign every commit with `git commit -s`; the sign-off certifies that you have the right to submit the contribution under the project license.

## Conduct and security

Participation is governed by `CODE_OF_CONDUCT.md`. Report vulnerabilities through the private process in `SECURITY.md`, never through a public issue.
