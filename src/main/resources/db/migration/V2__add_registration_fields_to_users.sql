-- Adds required multi-tenancy and registration fields to the users table.

ALTER TABLE users
    ADD COLUMN tenant_id VARCHAR(36) NOT NULL DEFAULT 'SYSTEM_GENERATED',
    ADD COLUMN name VARCHAR(100),
    ADD COLUMN phone VARCHAR(20),
    ADD COLUMN terms_accepted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN privacy_policy_accepted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN email_confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN email_confirmation_token VARCHAR(100);

-- Provide a unique constraint on tenant_id per user (tenant isolation)
ALTER TABLE users ADD CONSTRAINT uk_user_tenant UNIQUE (tenant_id);
