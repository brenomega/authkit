# Dependency degradation

Confirm the alert labels and UTC start time, then inspect `/actuator/health` and the Redis/PostgreSQL service health without bypassing fail-closed controls. For Redis, verify DNS, TLS/authentication, memory pressure and latency; restore the dependency, confirm `security_abuse_control_fail_closed_total` stops increasing, and run login, refresh, step-up and deletion smoke tests. Escalate if counters continue after dependency recovery. Record commands, metrics and the incident interval.
