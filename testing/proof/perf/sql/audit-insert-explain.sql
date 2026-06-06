-- Purpose: Verify critical audit writes remain simple inserts and supporting lookups use target/time indexes.
-- Required setup: security_events table exists.
-- Expected index for forensic reads: target user/time or tenant/time indexes from migrations.

EXPLAIN (ANALYZE, BUFFERS)
INSERT INTO security_events (
  id, event_type, outcome, severity, actor_user_id, target_user_id, tenant_id,
  ip_hash, user_agent_hash, details_json, created_at
) VALUES (
  gen_random_uuid(), 'LOGIN_SUCCESS', 'SUCCESS', 'LOW', :'user_id', :'user_id', :'tenant_id',
  'fixture-ip-hash', 'fixture-ua-hash', '{}', now()
);
