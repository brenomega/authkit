-- Multi-replica scheduler coordination and terminal email delivery state.

CREATE TABLE shedlock (
    name       VARCHAR(64)  NOT NULL,
    lock_until TIMESTAMPTZ  NOT NULL,
    locked_at  TIMESTAMPTZ  NOT NULL,
    locked_by  VARCHAR(255) NOT NULL,
    CONSTRAINT pk_shedlock PRIMARY KEY (name)
);

ALTER TABLE email_outbox
    DROP CONSTRAINT ck_email_outbox_status;

ALTER TABLE email_outbox
    ADD CONSTRAINT ck_email_outbox_status
        CHECK (status IN ('PENDING', 'PROCESSING', 'QUEUED', 'SENT', 'FAILED', 'DEAD'));
