ALTER TABLE passkey_credentials
    ADD CONSTRAINT ck_passkey_signature_count_nonnegative CHECK (signature_count >= 0);

ALTER TABLE users
    ADD CONSTRAINT ck_users_deletion_state CHECK (
        (account_state = 'DELETION_PENDING' AND deletion_requested_at IS NOT NULL
            AND deleted_at IS NULL AND anonymized_at IS NULL)
        OR (account_state = 'ANONYMIZED' AND deletion_requested_at IS NOT NULL
            AND deleted_at IS NOT NULL AND anonymized_at IS NOT NULL)
        OR (account_state IN ('ACTIVE', 'SUSPENDED') AND deletion_requested_at IS NULL
            AND deleted_at IS NULL AND anonymized_at IS NULL)
    );
