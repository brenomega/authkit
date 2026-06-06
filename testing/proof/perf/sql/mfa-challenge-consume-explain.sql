-- Purpose: Verify MFA login challenge consume uses the composite primary key.
-- Required setup: auth_mfa_login_challenges contains a row for :user_id and :jti.
-- Expected index: auth_mfa_login_challenges primary key.

EXPLAIN (ANALYZE, BUFFERS)
DELETE FROM auth_mfa_login_challenges
WHERE user_id = :'user_id'
  AND jti = :'jti'
  AND token_hash = :'token_hash'
  AND expires_at > now();
