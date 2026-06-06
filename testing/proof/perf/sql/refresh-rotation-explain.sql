-- Purpose: Verify refresh rotation locks and updates one active session/family efficiently.
-- Required setup: auth_refresh_sessions and auth_refresh_token_families contain an active token family.
-- Expected indexes: auth_refresh_sessions primary key, uq_auth_refresh_sessions_jti, auth_refresh_token_families primary key.

EXPLAIN (ANALYZE, BUFFERS)
SELECT s.user_id, s.jti, s.token_hash, s.family_id, f.active_jti
FROM auth_refresh_sessions s
JOIN auth_refresh_token_families f ON f.family_id = s.family_id
WHERE s.user_id = :'user_id'
  AND s.jti = :'jti'
FOR UPDATE;
