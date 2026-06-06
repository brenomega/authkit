# Provisional Performance Budgets

These budgets are conservative proof thresholds. They should be tightened or loosened only after measured reports.

| Tier | Login p95 | Refresh p95 | Session list p95 | OAuth introspection p95 | Max outbox backlog age | Max Hikari pending wait | Critical audit drops |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 00H | 1500 ms | 400 ms | 500 ms | 400 ms | 10 min | 0 sustained | 0 |
| 0S | 1200 ms | 300 ms | 400 ms | 300 ms | 5 min | 0 sustained | 0 |
| 1S | 1000 ms | 250 ms | 300 ms | 250 ms | 2 min | 0 sustained | 0 |
| 0P | 1500 ms | 500 ms | 700 ms | 500 ms | 10 min | 0 sustained | 0 |

## Notes

- Login includes Argon2 verification and may be CPU-bound.
- Refresh must remain fast and must not accept replay.
- Session list must use bounded pages and cursor ownership.
- OAuth introspection is a resource-server hot path and should not depend on first-party session lookup.
- Critical audit drops are never acceptable; critical audit persistence failures should fail closed.
