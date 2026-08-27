# AuthKit Spring Resource Server Sample

This sample is a standalone host application that validates AuthKit OAuth access tokens. It is not part of AuthKit runtime and must not be used as a production template without review.

## What It Proves

- JWT signature validation through AuthKit JWKS.
- Exact issuer validation.
- Exact audience validation for the resource API.
- `token_use=oauth_access` enforcement.
- Host-resource authorization using an OAuth client scope.
- `tenant_id` displayed only as an opaque per-person partition, never as organization authority.
- Rejection of first-party access tokens and ID tokens.

## Configuration

The sample reads these environment variables:

```bash
export AUTHKIT_ISSUER=http://localhost:8080
export AUTHKIT_JWKS_URI=http://localhost:8080/.well-known/jwks.json
export AUTHKIT_ACCEPTED_AUDIENCE=sample-resource-api
export AUTHKIT_ACCEPTED_TOKEN_USE=oauth_access
```

Use local-only defaults for development. In production, `AUTHKIT_ISSUER` must be the exact issuer in tokens and `AUTHKIT_JWKS_URI` must point to the trusted AuthKit JWKS endpoint over TLS.

## Start AuthKit Locally

From the repository root, start the documented local manual harness or install the golden path. The golden production command is:

```bash
docker compose --env-file deploy/golden/.env -f deploy/golden/compose.yml up -d --build
```

Replace every `CHANGE-ME` value before using any non-local environment.

## Create Or Obtain An OAuth Client

Create an AuthKit OAuth client whose client id is the resource API audience:

```text
client_id: sample-resource-api
redirect_uri: http://localhost:3000/callback
scopes: openid email profile sample.read
```

Use the AuthKit admin API or seeded test data in your local environment. Do not paste client secrets into this README or shell history.

## Get A Test Token

For generated contract fixtures:

```bash
testing/proof/fixtures/generate-test-tokens.sh
```

The generated `valid-oauth-access.jwt` is signed with the repository test key. It is suitable only for local/HML proof runs where AuthKit is configured with the matching test public key.

For real OAuth testing, complete the authorization-code + PKCE flow against AuthKit and use the returned access token.

## Run The Sample

```bash
cd samples/resource-server-spring
mvn spring-boot:run
```

Call the sample:

```bash
TOKEN="$(cat ../../target/contract-fixtures/valid-oauth-access.jwt)"
curl -sS -H "Authorization: Bearer ${TOKEN}" http://localhost:8081/sample/me
```

If the sample runs on the same port as AuthKit, set `SERVER_PORT=8081`.

## Run Negative Token Tests

```bash
cd samples/resource-server-spring
mvn test
```

The tests cover token class, issuer, audience, and missing-scope failures.

## Host Responsibilities

The host application must still:

- Validate the exact issuer and accepted audience for each API.
- Require `token_use=oauth_access`.
- Treat `tenant_id` only as AuthKit's opaque personal partition. It is not an organization or host-product role boundary.
- Enforce client scopes and the host application's own object/policy data server-side. `PLATFORM_ADMIN` authorizes only AuthKit's control plane.
- Reject ID tokens and first-party AuthKit tokens.
- Refresh JWKS on unknown `kid` once, then reject.
- Keep AuthKit issuer/JWKS configuration under deployment control, not user input.
