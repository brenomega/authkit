ALTER TABLE auth_refresh_sessions
    ADD COLUMN public_session_id UUID,
    ADD COLUMN last_seen_at TIMESTAMPTZ,
    ADD COLUMN initial_amr VARCHAR(160),
    ADD COLUMN user_agent_summary VARCHAR(200),
    ADD COLUMN device_label VARCHAR(80),
    ADD COLUMN creation_ip_masked VARCHAR(64),
    ADD COLUMN last_ip_masked VARCHAR(64);

UPDATE auth_refresh_sessions
SET public_session_id = gen_random_uuid(),
    last_seen_at = updated_at,
    initial_amr = '',
    user_agent_summary = 'Unknown client',
    creation_ip_masked = 'unknown',
    last_ip_masked = 'unknown'
WHERE public_session_id IS NULL;

ALTER TABLE auth_refresh_sessions
    ALTER COLUMN public_session_id SET NOT NULL,
    ALTER COLUMN last_seen_at SET NOT NULL,
    ALTER COLUMN initial_amr SET NOT NULL,
    ALTER COLUMN user_agent_summary SET NOT NULL,
    ALTER COLUMN creation_ip_masked SET NOT NULL,
    ALTER COLUMN last_ip_masked SET NOT NULL;

CREATE UNIQUE INDEX uq_auth_refresh_sessions_public_id
    ON auth_refresh_sessions (public_session_id);

ALTER TABLE auth_refresh_sessions
    ADD CONSTRAINT ck_auth_refresh_sessions_temporal_order
        CHECK (created_at <= last_seen_at AND last_seen_at <= expires_at),
    ADD CONSTRAINT ck_auth_refresh_sessions_device_label_nonblank
        CHECK (device_label IS NULL OR length(trim(device_label)) > 0);
