# Threat model

[English](THREAT_MODEL.md) | [Português (Brasil)](THREAT_MODEL-ptBR.md)

English is authoritative when translations differ.

## Scope and trust boundaries

The protected assets are identities, authenticators, first-party and OAuth token lineages, consent/audit evidence, signing and encryption keys, email ceremony state, and operator availability. Trust boundaries are the public TLS proxy, browser cookie/CSRF boundary, OAuth clients and resource servers, social OIDC providers, SMTP/Resend, the internal worker network plus token, PostgreSQL, Redis, and the release supply chain.

## Adversaries, controls, and residual risk

| Threat / adversary | Assumption or abuse case | Preventive and detective controls | Residual risk / operator action |
|---|---|---|---|
| Credential stuffing and password DoS | Remote attacker has email/password corpora or sends expensive inputs | Bounded input, Argon2 semaphore, layered IP/device/email limits, lockout, HIBP, metrics | Distributed limits depend on Redis; high-risk paths fail closed and the dependency runbook applies. |
| Session or refresh theft | Bearer/cookie is copied or replayed | HttpOnly Secure Strict cookie, CSRF, refresh rotation/family replay revocation, JTI live state, short access TTL | Access tokens remain usable until TTL unless account/session state rejects them; investigate reuse immediately. |
| Cross-token substitution | OAuth, ID, or first-party JWT is presented at another boundary | Exact `token_use`, one exact audience, required claims, endpoint-specific decoder, live session/family state | Downstream services must validate the same class and refresh JWKS on unknown `kid`. |
| OAuth redirect/code attack | Malicious client alters redirect, PKCE, state or nonce | Exact registered redirect without fragments, S256 PKCE, one-time code/transaction, required state and OIDC nonce | A compromised client origin remains able to misuse its own authorization; revoke the client. |
| Tenant data access | Authenticated tenant attempts cross-tenant identifiers | UUID-typed Hibernate tenant filter, explicit tenant checks, opaque not-found responses, platform-admin separation | Platform administrators are global by design and require local step-up plus a second factor. |
| Social account creation/link takeover | Federated subject collides with local email or bypasses restricted signup | Immutable issuer+subject, no email auto-link, explicit step-up linking, registration policy on every new identity | Security depends on provider issuer integrity and configured allowlist. |
| One-time ceremony race/replay | Concurrent confirmation, recovery, TOTP, passkey, OAuth or email-change submissions | Row locks/conditional transitions, hashed state, expiry, real-store concurrency tests | Availability failures may reject a valid attempt; they must never produce two winners. |
| Audit suppression or cross-store rollback | Database/Redis failure occurs between mutation, audit, and revocation | Critical audit joins SQL transaction; external revocations run after commit; recovery token activates only after durable outbox commit | A post-commit cleanup failure requires reconciliation and alert response, while live DB account state remains authoritative. |
| Email duplicate or token leak | Crash occurs after provider acceptance; URLs leak through query/referrer | Outbox identity, provider idempotency or SMTP stable Message-ID/dedupe, fragment tokens, no secret logs | SMTP relay must demonstrably dedupe within reclaim window; email remains at-least-once outside that guarantee. |
| Internal worker compromise | Internet caller obtains token or spoofs proxy headers | Public proxy does not route internal/Prometheus; trusted network and worker token are independent; forwarded headers rebuilt | Compromise of both internal network and current token grants worker access; rotate and investigate. |
| Key/supply-chain compromise | Old key remains active, artifact is replaced, or secret enters source | Active/retiring/revoked key sets, unknown-kid rejection, SBOM, checksum, signature, provenance, secret/static/container scans | Operator must protect signing keys and complete rotations; follow the key-rotation runbook. |
| Resource exhaustion | Oversized/chunked bodies, hostile bursts, pool exhaustion | Streaming bounds including DELETE, timeouts, rate limits, pool/Argon2 metrics, 2-vCPU/4-GiB performance gate | Sustained dependency saturation can cause fail-closed availability loss; capacity plan from measured baseline. |

Security assumptions and operational invariants are expanded in [SECURITY_MODEL.md](SECURITY_MODEL.md); evidence is linked in [TRACEABILITY.md](TRACEABILITY.md).
