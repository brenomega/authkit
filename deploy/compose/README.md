# Unsupported development previews

These Redis-direct, JDBC-direct, and RabbitMQ Compose files are opt-in development previews with Mailpit. They are excluded from v0.1 production instructions and release gates. They intentionally do not provide the mounted production secrets, TLS, templates, separated database roles, or provider evidence required by `deploy/golden`.

JDBC token storage and RabbitMQ dispatch retain unit/integration coverage but have no dedicated current candidate smoke or operational proof. Presence here is not a support claim. Do not expose their ports or reuse placeholder credentials.
