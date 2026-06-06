# AuthKit Spring Resource Server Sample

This sample is a standalone host application that validates AuthKit OAuth access tokens. It is not part of AuthKit runtime and must not be used as a production template without review.

## What It Proves

- JWT signature validation through AuthKit JWKS.
- Exact issuer validation.
- Exact audience validation for the resource API.
- `token_use=oauth_access` enforcement.
- Tenant path authorization using the token `tenant_id` claim.
- Scope or role enforcement for admin-like routes.
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

From the repository root, start the AuthKit tier you want to test. For example, with a Redis-direct compose stack:

```bash
cp deploy/compose/.env.redis-direct.example deploy/compose/.env
docker compose --env-file deploy/compose/.env -f deploy/compose/docker-compose.redis-direct.yml up --build
```

Replace every `CHANGE-ME` value before using any non-local environment.

## Create Or Obtain An OAuth Client

Create an AuthKit OAuth client whose client id is the resource API audience:

```text
client_id: sample-resource-api
redirect_uri: http://localhost:3000/callback
scopes: openid email profile admin
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

The tests cover token class, issuer, audience, tenant, and admin-scope failures.

## Tenant Validation

The tenant id in the route must match the token claim:

```bash
curl -H "Authorization: Bearer ${TOKEN}" http://localhost:8081/sample/tenant/<tenant_id>/profile
```

The sample never accepts tenant, role, or scope values from request bodies or arbitrary headers. Host systems must apply the same rule to every tenant-scoped object lookup.

## Host Responsibilities

The host application must still:

- Validate the exact issuer and accepted audience for each API.
- Require `token_use=oauth_access`.
- Enforce tenant/object authorization server-side.
- Enforce scopes or roles server-side.
- Reject ID tokens and first-party AuthKit tokens.
- Refresh JWKS on unknown `kid` once, then reject.
- Keep AuthKit issuer/JWKS configuration under deployment control, not user input.
