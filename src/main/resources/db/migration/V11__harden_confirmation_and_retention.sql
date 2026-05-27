-- Prompt 1 hardening: expiring email confirmation tokens and safe user purges.

ALTER TABLE users
    ADD COLUMN email_confirmation_expires_at TIMESTAMPTZ;

CREATE INDEX idx_users_email_confirmation_expiry
    ON users (email_confirmation_expires_at)
    WHERE email_confirmation_token IS NOT NULL;

ALTER TABLE mfa_totp_credentials
    DROP CONSTRAINT fk_mfa_totp_credentials_user,
    ADD CONSTRAINT fk_mfa_totp_credentials_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

ALTER TABLE mfa_backup_codes
    DROP CONSTRAINT fk_mfa_backup_codes_user,
    ADD CONSTRAINT fk_mfa_backup_codes_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

ALTER TABLE passkey_credentials
    DROP CONSTRAINT fk_passkey_credentials_user,
    ADD CONSTRAINT fk_passkey_credentials_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

ALTER TABLE passkey_challenges
    DROP CONSTRAINT fk_passkey_challenges_user,
    ADD CONSTRAINT fk_passkey_challenges_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

ALTER TABLE oauth_consents
    DROP CONSTRAINT fk_oauth_consents_user,
    ADD CONSTRAINT fk_oauth_consents_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;

ALTER TABLE oauth_authorization_codes
    DROP CONSTRAINT fk_oauth_authorization_codes_user,
    ADD CONSTRAINT fk_oauth_authorization_codes_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE;
