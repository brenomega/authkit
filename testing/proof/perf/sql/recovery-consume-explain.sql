-- Purpose: Verify password recovery token consume uses the email hash primary key.
-- Required setup: auth_recovery_tokens contains a row for :email_hash.
-- Expected index: auth_recovery_tokens primary key.

EXPLAIN (ANALYZE, BUFFERS)
DELETE FROM auth_recovery_tokens
WHERE email_hash = :'email_hash'
  AND token_hash = :'token_hash'
  AND expires_at > now();
