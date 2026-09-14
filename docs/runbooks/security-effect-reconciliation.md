# Security-effect reconciliation

Alert: `AuthKitSecurityEffectReconciliationPending`.

This alert means a PostgreSQL-committed security boundary is already enforcing a newer `security_version`, but its physical Redis cleanup has not completed within five minutes. Stale credentials remain denied by PostgreSQL-backed live-state validation; do not bypass that validation or edit security versions.

1. Record the alert start, candidate/image digest, `security_effects_outstanding`, `security_effects_retry_total`, Redis health, and affected outbox IDs without copying raw credentials.
2. Restore Redis reachability, authentication, memory headroom, and command latency. Confirm PostgreSQL and the scheduler lock are healthy.
3. Observe the automatic retry. A successful run increments `security_effects_completed_total` and returns the outstanding gauge to zero.
4. Verify stale refresh/session state is physically absent and any explicitly preserved current session still works. For recovery effects, verify the digest-keyed recovery state is absent.
5. If the task remains `PROCESSING` beyond the claim timeout, retain logs and allow the reconciler to reclaim it. Do not delete or mark a row complete manually.
6. Escalate as an integrity incident if the backlog grows, the durable PostgreSQL boundary is unavailable, or a stale credential is accepted. Preserve request/audit IDs and the proof window.

Close the incident only after the outbox is complete, the gauge is zero, Redis state matches the committed boundary, and no critical audit or integrity error occurred.
