-- MFA baseline: encrypted TOTP credentials and hashed one-time backup codes.

CREATE TABLE mfa_totp_credentials (
    id                  UUID          NOT NULL,
    user_id             UUID          NOT NULL,
    tenant_id           UUID          NOT NULL,
    encrypted_secret    VARCHAR(512)  NOT NULL,
    confirmed           BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ   NOT NULL,
    confirmed_at        TIMESTAMPTZ,
    disabled_at         TIMESTAMPTZ,
    last_used_time_step BIGINT,

    CONSTRAINT pk_mfa_totp_credentials PRIMARY KEY (id),
    CONSTRAINT fk_mfa_totp_credentials_user
        FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE UNIQUE INDEX uq_mfa_totp_one_active_per_user
    ON mfa_totp_credentials (user_id)
    WHERE confirmed = TRUE AND disabled_at IS NULL;

CREATE INDEX idx_mfa_totp_credentials_user
    ON mfa_totp_credentials (user_id, created_at DESC);

CREATE INDEX idx_mfa_totp_credentials_tenant
    ON mfa_totp_credentials (tenant_id, created_at DESC);

CREATE TABLE mfa_backup_codes (
    id         UUID         NOT NULL,
    user_id    UUID         NOT NULL,
    tenant_id  UUID         NOT NULL,
    code_hash  VARCHAR(64)  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL,
    used_at    TIMESTAMPTZ,

    CONSTRAINT pk_mfa_backup_codes PRIMARY KEY (id),
    CONSTRAINT fk_mfa_backup_codes_user
        FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE UNIQUE INDEX uq_mfa_backup_codes_active_hash
    ON mfa_backup_codes (user_id, code_hash)
    WHERE used_at IS NULL;

CREATE INDEX idx_mfa_backup_codes_user_unused
    ON mfa_backup_codes (user_id, created_at DESC)
    WHERE used_at IS NULL;

CREATE INDEX idx_mfa_backup_codes_tenant
    ON mfa_backup_codes (tenant_id, created_at DESC);
