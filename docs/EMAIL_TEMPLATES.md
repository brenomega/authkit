# Operator email-template contract

[English](EMAIL_TEMPLATES.md) | [Português (Brasil)](EMAIL_TEMPLATES-ptBR.md)

English is authoritative when translations differ.

The integrating application owns all production copy, HTML, localization, legal text, and branding. AuthKit does not generate those assets. It loads a read-only operator directory at startup, rejects a missing or invalid template, and performs only non-executable escaped substitution.

For each stem below, provide `<stem>.subject.txt` and `<stem>.body.html`:

| Stem | Purpose | Required placeholder |
| --- | --- | --- |
| `email-confirmation` | Verify a new account | `{{action_url}}` |
| `password-recovery` | Reset a password | `{{action_url}}` |
| `password-changed` | Notify after password change | none |
| `email-change-confirmation` | Verify the new address | `{{action_url}}` |
| `email-change-requested` | Notify the old address | none |
| `email-changed` | Notify after completion | none |
| `email-change-cancelled` | Notify after cancellation | none |

Subjects must be one non-empty line of at most 255 characters. Bodies must be non-empty UTF-8 files no larger than the configured limit (default 64 KiB). The renderer rejects scripts, JavaScript URLs, inline event handlers, iframe/object/embed elements, path traversal, symlink escape, unknown/malformed placeholders, and missing action URLs. Substituted values are HTML-escaped.

`action_url` carries the one-time secret in the URL fragment, not its query string. The frontend must read the fragment into memory, immediately remove it with `history.replaceState`, submit it in the JSON request body over TLS, and never place it in logs, analytics, referrers, persistence, or third-party error reports.

SMTP receives one transport attempt for each durable outbox claim and preserves the exact outbox UUID in both `Message-ID` and `X-AuthKit-Message-Id` across reclaim. Because SMTP itself has no portable idempotency command, the production relay must demonstrably deduplicate that stable identity through an acceptance→crash→reclaim drill; production startup requires the operator's explicit `AUTH_EMAIL_SMTP_DEDUPLICATION_GUARANTEED=true` assertion. A relay that cannot satisfy the drill is not a supported v0.1 production SMTP configuration. Resend uses its provider idempotency facility with bounded internal retries. `ACCEPTED` and `accepted_at` mean provider acceptance only, never inbox delivery, reading, or spam-folder placement.
