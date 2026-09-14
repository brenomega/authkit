# Scheduler failure

Identify the failed `job` label and verify distributed lock ownership and database time. Inspect the last run, lock row, PostgreSQL health and application logs. Restore the dependency, execute one bounded manual run of the same job, and prove the failure counter stops increasing. Never run two retention or anonymization workers concurrently.
