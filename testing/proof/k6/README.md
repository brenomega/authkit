# k6 Proof Scripts

Install k6 from the official packages for your OS, then run scripts from the repository root.

Examples:

```bash
AUTHKIT_BASE_URL=http://localhost:8080 k6 run testing/proof/k6/login-refresh.js
AUTHKIT_BASE_URL=http://localhost:8080 \
AUTHKIT_INTROSPECTION_URL=http://localhost:8080/api/v1/internal/tokens/introspect \
AUTHKIT_WORKER_TOKEN_FILE=/run/secrets/worker_token \
AUTHKIT_K6_LOGIN_EMAIL_FILE=/run/secrets/load_email \
AUTHKIT_K6_LOGIN_PASSWORD_FILE=/run/secrets/load_password \
PROOF_REPORT_DIR=target/proof/load \
ALLOW_SHORT_LOAD_PROOF=true K6_VUS=4 K6_TARGET_RPS=0.8 K6_DURATION=2m testing/proof/run-reference-load.sh
```

The two-minute command is harness validation only. Remove `ALLOW_SHORT_LOAD_PROOF` and use `K6_DURATION=4h` or longer for Gate 10.

The scripts are proof harnesses, not capacity claims. Use `docs/proof/templates/proof-report-template.md` to record the host, tier, config, and metrics for every run.

`K6_INSECURE_SKIP_TLS_VERIFY=true` exists only to validate the harness against an ephemeral local CA. A release proof must validate the real certificate and must not set it.
For a local certificate hostname that is absent from host DNS, pass an explicit test-only Docker mapping such as `AUTHKIT_LOAD_HOST_ALIAS=authkit.local:172.30.0.10`; do not use it to bypass production DNS validation. When introspection is on the private golden Compose network, set `AUTHKIT_LOAD_DOCKER_NETWORK=authkit-golden_internal`, `AUTHKIT_LOAD_DOCKER_IP=172.30.0.20`, and `AUTHKIT_INTROSPECTION_URL=http://authkit:8080/api/v1/internal/tokens/introspect`. The fixed `.20` source matches the dedicated worker CIDR; never trust Caddy (`.10`) or the entire subnet.

The mixed workload logs in once per VU, then deterministically exercises refresh rotation, authenticated session listing, live worker introspection, and health. Initial logins are staggered by `K6_LOGIN_STAGGER_SECONDS` (default `4`) so harness synchronization does not exceed the bounded Argon2 admission pool before the steady workload starts. `K6_TARGET_RPS` controls the aggregate steady offered rate; its default is `0.8` requests/second across four VUs so the single-source proof remains below the normative 60 requests/minute client-IP budget. Capacity beyond that security boundary must use independent, non-spoofed client addresses. The controlled hostile burst proves excess traffic is rejected rather than silently raising the security limits. The workload applies the published endpoint-specific p95 thresholds and treats throttling or authentication loss as a failed proof rather than hiding it as an expected response. Pass credentials through the environment or a wrapper that reads mounted secret files; never commit them.

Do not print access tokens, refresh tokens, reset tokens, or passwords in k6 output.
