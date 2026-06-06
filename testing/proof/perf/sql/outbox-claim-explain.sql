-- Purpose: Verify the email outbox claim query uses due-status and next-attempt indexes.
-- Required setup: email_outbox contains pending, failed, queued, sent, and dead rows.
-- Expected index: ix_email_outbox_status_next_attempt or equivalent migration-created hot-path index.

EXPLAIN (ANALYZE, BUFFERS)
SELECT id
FROM email_outbox
WHERE status IN ('PENDING', 'FAILED', 'QUEUED')
  AND next_attempt_at <= now()
  AND (locked_at IS NULL OR locked_at < now() - interval '5 minutes')
ORDER BY next_attempt_at ASC, created_at ASC
LIMIT 50
FOR UPDATE SKIP LOCKED;
