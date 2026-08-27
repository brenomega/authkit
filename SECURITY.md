# Security policy

## Reporting a vulnerability

Do not disclose an unpatched vulnerability in a public issue, discussion, pull request, or chat. Use [GitHub private vulnerability reporting](https://github.com/brenomega/authkit/security/advisories/new). Include the affected version or commit, deployment mode, reproduction steps, impact, and any suggested mitigation. Do not include real credentials or personal data.

The maintainers coordinate validation, remediation, disclosure timing, and credit with the reporter. Community maintenance is best-effort: there is no service-level agreement or guaranteed response time. If immediate containment is required, operators should follow their own incident-response plan and may temporarily disable the affected capability.

## Supported versions

Before v0.1.0 is released, only the current release candidate is evaluated. After release, only the latest `0.1.x` patch line is supported. Older, experimental, preview, and unsupported deployment paths do not receive a production-support promise.

## Security boundaries

AuthKit provides an application security audit trail, not WORM storage or a compliance certification. Operators remain responsible for TLS, network isolation, secret management, backups, monitoring, provider credentials, incident response, legal text, and downstream authorization. See `docs/SECURITY_MODEL.md` and the version-bound support matrix.
