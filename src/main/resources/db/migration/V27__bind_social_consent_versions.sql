-- Bind the exact consent texts accepted when a social OIDC ceremony starts.
-- In-flight pre-upgrade ceremonies are short lived and cannot truthfully be
-- attributed to a version, so deployment invalidates them instead of guessing.
DELETE FROM social_login_transactions;

ALTER TABLE social_login_transactions
    ADD COLUMN terms_version VARCHAR(64) NOT NULL,
    ADD COLUMN privacy_policy_version VARCHAR(64) NOT NULL,
    ADD COLUMN lawful_basis VARCHAR(64) NOT NULL;
