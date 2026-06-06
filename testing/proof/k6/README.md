# k6 Proof Scripts

Install k6 from the official packages for your OS, then run scripts from the repository root.

Examples:

```bash
AUTHKIT_BASE_URL=http://localhost:8080 k6 run testing/proof/k6/login-refresh.js
AUTHKIT_BASE_URL=http://localhost:8080 K6_VUS=5 K6_DURATION=2m k6 run testing/proof/k6/mixed-auth-workload.js
```

The scripts are proof harnesses, not capacity claims. Use `docs/proof/templates/proof-report-template.md` to record the host, tier, config, and metrics for every run.

Do not print access tokens, refresh tokens, reset tokens, or passwords in k6 output.
