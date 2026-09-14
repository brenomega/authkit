# Health and readiness failure

Capture the UTC interval and `/actuator/health` component statuses. Check PostgreSQL, Redis, disk, JVM memory and application startup validation in that order. Restore dependencies without disabling production validation or security controls. Readiness is recovered only after dependency health is green and authenticated smoke tests pass.
