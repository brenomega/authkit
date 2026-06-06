# AuthKit Contract Fixtures

These fixtures document the token classes AuthKit and downstream resource APIs must accept or reject. The JSON files under `tokens/` are metadata only; they do not contain signed JWTs, secrets, or reusable credentials.

## Token Classes

AuthKit uses three mutually exclusive token classes:

- `first_party_access`: accepted by AuthKit first-party APIs only when the configured API audience matches and the `jti` maps to an active server-side session.
- `oauth_access`: accepted by OAuth userinfo/introspection/revocation and by downstream resource APIs when issuer, audience, tenant, scope, expiry, and key state match.
- `id_token`: accepted by an OAuth client as an authentication result only. It must never authorize API calls.

Legacy first-party tokens without `token_use` are documented only to preserve a temporary AuthKit compatibility path. Downstream resource APIs must reject them.

## Fixture Metadata

Each `tokens/*.json` file includes:

- `name`: stable fixture id.
- `description`: what the case represents.
- `tokenClass`: intended token class or invalid class.
- `claims`: representative claims.
- `expectedAuthKitResult`: expected behavior at AuthKit boundaries.
- `expectedIntegratorResult`: expected behavior at resource-server boundaries.
- `expectedStatus`: expected HTTP status for the primary negative case.
- `reason`: the security property being proved.

## Generate Signed Test Tokens

Run:

```bash
testing/proof/fixtures/generate-test-tokens.sh
```

The generator uses only the committed test key in `src/main/resources/test-keys/` and writes signed JWTs to `target/contract-fixtures/`. It never prints token values or private key material. Generated files are ignored by Git through the repository-wide `target/` rule.

## Run Negative AuthKit Contract Checks

Start AuthKit in a local or HML environment, generate tokens, then run:

```bash
AUTHKIT_BASE_URL=http://localhost:8080 testing/proof/smoke/negative-contracts.sh
```

The script refuses production-looking hostnames unless `ALLOW_PRODUCTION_PROOF=true` is set for an approved proof window. It prints fixture names and statuses only, never token values.

## Expected Boundary Behavior

| Fixture | AuthKit first-party API | OAuth userinfo | Generic resource API |
| --- | --- | --- | --- |
| `valid-first-party-access` | Accepted only with active session | Rejected | Rejected |
| `valid-oauth-access` | Rejected | Accepted when scope/audience match | Accepted when issuer/audience/tenant/scope match |
| `valid-id-token` | Rejected | Rejected | Rejected |
| `wrong-audience` | Rejected | Rejected | Rejected |
| `wrong-issuer` | Rejected | Rejected | Rejected |
| `expired-token` | Rejected | Rejected | Rejected |
| `missing-token-use` | Temporary legacy AuthKit-only path | Rejected | Rejected |
| `missing-tenant-id` | Rejected for tenant flows | Rejected for tenant flows | Rejected for tenant flows |
| `tenant-mismatch` | Not applicable | Not applicable | Rejected |
| `revoked-session` | Rejected | Rejected | Rejected |
| `revoked-key-id` | Rejected | Rejected | Rejected |
| `oauth-token-used-on-first-party-api` | Rejected | Accepted when otherwise valid | Accepted when otherwise valid |
| `first-party-token-used-on-oauth-userinfo` | Accepted only with active session | Rejected | Rejected |
| `id-token-used-on-api` | Rejected | Rejected | Rejected |
