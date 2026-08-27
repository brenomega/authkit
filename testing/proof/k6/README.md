# k6 Proof Scripts

Install k6 from the official packages for your OS, then run scripts from the repository root.

Examples:

```bash
AUTHKIT_BASE_URL=http://localhost:8080 k6 run testing/proof/k6/login-refresh.js
AUTHKIT_BASE_URL=http://localhost:8080 K6_VUS=5 K6_DURATION=2m k6 run testing/proof/k6/mixed-auth-workload.js
```

The scripts are proof harnesses, not capacity claims. Use `docs/proof/templates/proof-report-template.md` to record the host, tier, config, and metrics for every run.

`K6_INSECURE_SKIP_TLS_VERIFY=true` exists only to validate the harness against an ephemeral local CA. A release proof must validate the real certificate and must not set it.
For a local certificate hostname that is absent from host DNS, pass an explicit test-only Docker mapping such as `AUTHKIT_LOAD_HOST_ALIAS=authkit.local:127.0.0.1`; do not use it to bypass production DNS validation.

The mixed workload records deliberate high-risk login throttling as `auth_login_throttled`; HTTP 429 is contractually handled rather than counted as a transport failure. A nonzero counter still requires explicit capacity/abuse-control disposition and must never be hidden when evaluating release throughput.

Do not print access tokens, refresh tokens, reset tokens, or passwords in k6 output.
