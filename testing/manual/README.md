# Local manual-flow harness

This harness is test-only. It starts ephemeral PostgreSQL 17, Redis 7, and
Mailpit on loopback ports; it is not a production topology and proves no real
SMTP-provider acceptance.

```bash
docker compose -f testing/manual/compose.yml up -d --wait
testing/manual/run-app.sh
```

In another terminal, call `http://127.0.0.1:18026/api/v1/messages` to inspect
test mail and exercise the public endpoints at `http://127.0.0.1:18080`.

Stop the Java process, then remove only this harness's temporary containers:

```bash
docker compose -f testing/manual/compose.yml down
```
