ALTER TABLE security_effect_outbox
    ADD COLUMN recovery_token_digest VARCHAR(64),
    ADD COLUMN recovery_expires_at TIMESTAMPTZ,
    ADD COLUMN email_message_id UUID,
    DROP CONSTRAINT ck_security_effect_type,
    DROP CONSTRAINT ck_security_effect_payload;

ALTER TABLE security_effect_outbox
    ADD CONSTRAINT ck_security_effect_type CHECK (
        effect_type IN ('REVOKE_STALE_SESSIONS', 'REVOKE_RECOVERY_TOKEN', 'ACTIVATE_RECOVERY_TOKEN')),
    ADD CONSTRAINT ck_security_effect_payload CHECK (
        (effect_type = 'REVOKE_STALE_SESSIONS' AND user_id IS NOT NULL AND target_version IS NOT NULL
            AND recovery_email_digest IS NULL AND recovery_token_digest IS NULL
            AND recovery_expires_at IS NULL AND email_message_id IS NULL)
        OR (effect_type = 'REVOKE_RECOVERY_TOKEN' AND user_id IS NULL AND target_version IS NULL
            AND preserved_session_jti IS NULL AND recovery_email_digest IS NOT NULL
            AND recovery_token_digest IS NULL AND recovery_expires_at IS NULL AND email_message_id IS NULL)
        OR (effect_type = 'ACTIVATE_RECOVERY_TOKEN' AND user_id IS NOT NULL AND target_version IS NOT NULL
            AND preserved_session_jti IS NULL AND recovery_email_digest IS NOT NULL
            AND recovery_token_digest IS NOT NULL AND recovery_expires_at IS NOT NULL AND email_message_id IS NOT NULL));

ALTER TABLE email_outbox DROP CONSTRAINT ck_email_outbox_status;
ALTER TABLE email_outbox ADD CONSTRAINT ck_email_outbox_status CHECK (
    status IN ('PENDING', 'WAITING_ACTIVATION', 'CANCELLED', 'PROCESSING', 'QUEUED', 'ACCEPTED', 'FAILED', 'DEAD'));

CREATE TABLE auth_recovery_activations (id UUID PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX idx_auth_recovery_activations_expiry ON auth_recovery_activations (expires_at);
CREATE INDEX idx_security_effect_completed ON security_effect_outbox (completed_at) WHERE status = 'COMPLETED';
CREATE INDEX idx_security_effect_recovery ON security_effect_outbox (recovery_email_digest, created_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_recovery_activations TO authkit_runtime;
