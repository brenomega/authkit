-- Durable transactional outbox for email delivery.

CREATE TABLE email_outbox (
    id              UUID          NOT NULL,
    recipient       VARCHAR(320)  NOT NULL,
    subject         VARCHAR(255)  NOT NULL,
    body            TEXT          NOT NULL,
    status          VARCHAR(20)   NOT NULL,
    attempts        INTEGER       NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ   NOT NULL,
    locked_at       TIMESTAMPTZ,
    last_error      VARCHAR(1000),
    created_at      TIMESTAMPTZ   NOT NULL,
    updated_at      TIMESTAMPTZ   NOT NULL,

    CONSTRAINT pk_email_outbox PRIMARY KEY (id),
    CONSTRAINT ck_email_outbox_status
        CHECK (status IN ('PENDING', 'PROCESSING', 'SENT', 'FAILED'))
);

CREATE INDEX idx_email_outbox_due
    ON email_outbox (status, next_attempt_at, created_at)
    WHERE status IN ('PENDING', 'FAILED');

CREATE INDEX idx_email_outbox_processing_stale
    ON email_outbox (status, locked_at)
    WHERE status = 'PROCESSING';
