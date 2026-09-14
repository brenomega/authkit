# Authentication failure anomaly

Correlate the failed-login rate with request IDs, masked audit dimensions, lockouts,
global limiter and endpoint limiter counters. Preserve the incident time window.
Check provider/dependency health and recent configuration changes before treating
the event as an attack. Apply the documented edge limits, investigate affected
accounts, and verify successful authentication returns to baseline without
disabling password hashing, lockout, or fail-closed protection. Close the alert
only after the anomaly subsides and audit loss remains zero.
