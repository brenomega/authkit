-- Hot-path and governance indexes added after the Phase 8 performance audit.

CREATE INDEX idx_users_role_active
    ON users (role)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_users_deleted_at
    ON users (deleted_at)
    WHERE deleted_at IS NOT NULL;

CREATE INDEX idx_users_email_confirmation_token
    ON users (email_confirmation_token)
    WHERE email_confirmation_token IS NOT NULL;

CREATE INDEX idx_oauth_clients_created_at
    ON oauth_clients (created_at DESC);

CREATE INDEX idx_oauth_consents_user_granted
    ON oauth_consents (user_id, granted_at DESC);

CREATE INDEX idx_email_outbox_recipient_created_at
    ON email_outbox (recipient, created_at DESC);
