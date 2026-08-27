ALTER TABLE users
    ADD COLUMN pending_email VARCHAR(255),
    ADD COLUMN email_change_token_hash CHAR(64),
    ADD COLUMN email_change_expires_at TIMESTAMPTZ,
    ADD COLUMN email_change_requested_at TIMESTAMPTZ;

CREATE UNIQUE INDEX uq_users_pending_email
    ON users (LOWER(pending_email))
    WHERE pending_email IS NOT NULL;

CREATE UNIQUE INDEX uq_users_email_change_token_hash
    ON users (email_change_token_hash)
    WHERE email_change_token_hash IS NOT NULL;

ALTER TABLE users
    ADD CONSTRAINT ck_users_email_change_state
    CHECK (
        (pending_email IS NULL
            AND email_change_token_hash IS NULL
            AND email_change_expires_at IS NULL
            AND email_change_requested_at IS NULL)
        OR
        (pending_email IS NOT NULL
            AND email_change_token_hash IS NOT NULL
            AND email_change_expires_at IS NOT NULL
            AND email_change_requested_at IS NOT NULL
            AND email_change_expires_at > email_change_requested_at)
    );

ALTER TABLE auth_recovery_tokens
    ADD COLUMN claim_id VARCHAR(64),
    ADD COLUMN claim_until TIMESTAMPTZ;

ALTER TABLE auth_recovery_tokens
    ADD CONSTRAINT ck_auth_recovery_token_claim
    CHECK ((claim_id IS NULL AND claim_until IS NULL)
        OR (claim_id IS NOT NULL AND claim_until IS NOT NULL));
