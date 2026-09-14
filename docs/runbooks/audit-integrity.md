# Audit integrity or loss

Freeze privileged changes if `security_audit_fail_closed_total`, `security_audit_dropped_total`, or `security_events_dropped_total` increases. Check PostgreSQL availability, pool wait, disk capacity and the audit writer queue. Prove that a critical mutation rolls back, restore capacity, and reconcile business rows against critical security events for the alert interval. Do not synthesize or delete audit evidence. Escalate any unmatched mutation as a security incident.
