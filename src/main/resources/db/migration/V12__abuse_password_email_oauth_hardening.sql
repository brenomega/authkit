-- Prompt 2: abuse, password history, email delivery state, and OAuth hardening.

CREATE TABLE password_history (
    id            UUID         NOT NULL,
    user_id       UUID         NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL,

    CONSTRAINT pk_password_history PRIMARY KEY (id),
    CONSTRAINT fk_password_history_user
        FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX idx_password_history_user_created
    ON password_history (user_id, created_at DESC);

ALTER TABLE email_outbox
    ADD COLUMN provider_message_id VARCHAR(255),
    ADD COLUMN delivered_at TIMESTAMPTZ;

ALTER TABLE email_outbox
    DROP CONSTRAINT ck_email_outbox_status;

ALTER TABLE email_outbox
    ADD CONSTRAINT ck_email_outbox_status
        CHECK (status IN ('PENDING', 'PROCESSING', 'QUEUED', 'SENT', 'FAILED'));

DROP INDEX IF EXISTS idx_email_outbox_due;

CREATE INDEX idx_email_outbox_due
    ON email_outbox (status, next_attempt_at, created_at)
    WHERE status IN ('PENDING', 'FAILED', 'QUEUED');

CREATE INDEX idx_email_outbox_provider_message
    ON email_outbox (provider_message_id)
    WHERE provider_message_id IS NOT NULL;
