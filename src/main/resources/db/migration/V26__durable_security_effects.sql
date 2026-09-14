-- Durable credential invalidation and retryable external security effects.

ALTER TABLE users
    ADD COLUMN security_version BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN preserved_session_jti VARCHAR(36),
    ADD CONSTRAINT ck_users_security_version_nonnegative CHECK (security_version >= 0);

ALTER TABLE auth_refresh_sessions
    ADD COLUMN security_version BIGINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT ck_auth_refresh_sessions_security_version_nonnegative
        CHECK (security_version >= 0);

CREATE TABLE security_effect_outbox (
    id UUID PRIMARY KEY,
    effect_type VARCHAR(48) NOT NULL,
    user_id UUID,
    target_version BIGINT,
    preserved_session_jti VARCHAR(36),
    recovery_email_digest VARCHAR(64),
    status VARCHAR(20) NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    locked_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    last_error VARCHAR(1000),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT ck_security_effect_type CHECK (
        effect_type IN ('REVOKE_STALE_SESSIONS', 'REVOKE_RECOVERY_TOKEN')
    ),
    CONSTRAINT ck_security_effect_status CHECK (
        status IN ('PENDING', 'PROCESSING', 'FAILED', 'COMPLETED')
    ),
    CONSTRAINT ck_security_effect_attempts_nonnegative CHECK (attempts >= 0),
    CONSTRAINT ck_security_effect_payload CHECK (
        (effect_type = 'REVOKE_STALE_SESSIONS'
            AND user_id IS NOT NULL AND target_version IS NOT NULL
            AND recovery_email_digest IS NULL)
        OR
        (effect_type = 'REVOKE_RECOVERY_TOKEN'
            AND user_id IS NULL AND target_version IS NULL
            AND preserved_session_jti IS NULL AND recovery_email_digest IS NOT NULL)
    )
);

CREATE INDEX idx_security_effect_outbox_claim
    ON security_effect_outbox (status, next_attempt_at, created_at)
    WHERE status <> 'COMPLETED';

-- V23 installs default privileges for subsequent Flyway-owned tables. Keep the
-- explicit grant as a fail-safe for restored databases whose default ACLs were
-- created by a different owner before this migration runs.
GRANT SELECT, INSERT, UPDATE, DELETE ON security_effect_outbox TO authkit_runtime;
