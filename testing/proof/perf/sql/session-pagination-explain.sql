-- Purpose: Verify JDBC session keyset pagination uses the user/expires/jti index.
-- Required setup: auth_refresh_sessions populated with hundreds of active rows for :user_id.
-- Expected index: ix_auth_refresh_sessions_user_expires_jti.

EXPLAIN (ANALYZE, BUFFERS)
SELECT jti
FROM auth_refresh_sessions
WHERE user_id = :'user_id'
  AND expires_at > now()
  AND (:after_jti IS NULL OR jti > :'after_jti')
ORDER BY jti
LIMIT 51;
