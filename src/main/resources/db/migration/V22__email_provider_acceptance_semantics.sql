-- "Accepted" records provider/SMTP acceptance, not end-recipient delivery.
ALTER TABLE email_outbox DROP CONSTRAINT IF EXISTS ck_email_outbox_status;

UPDATE email_outbox SET status = 'ACCEPTED' WHERE status = 'SENT';

ALTER TABLE email_outbox
    ADD CONSTRAINT ck_email_outbox_status
        CHECK (status IN ('PENDING', 'PROCESSING', 'QUEUED', 'ACCEPTED', 'FAILED', 'DEAD'));

ALTER TABLE email_outbox RENAME COLUMN delivered_at TO accepted_at;
