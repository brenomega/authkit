-- Optional PostgreSQL-backed token/session state for explicit single-instance tiers.

CREATE TABLE auth_refresh_token_families (
    family_id  VARCHAR(64)  NOT NULL,
    user_id    UUID         NOT NULL,
    active_jti VARCHAR(64)  NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_auth_refresh_token_families PRIMARY KEY (family_id)
);

CREATE INDEX ix_auth_refresh_token_families_user
    ON auth_refresh_token_families (user_id, expires_at);

CREATE TABLE auth_refresh_sessions (
    user_id    UUID         NOT NULL,
    jti        VARCHAR(64)  NOT NULL,
    token_hash CHAR(64)     NOT NULL,
    family_id  VARCHAR(64)  NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_auth_refresh_sessions PRIMARY KEY (user_id, jti)
);

CREATE UNIQUE INDEX uq_auth_refresh_sessions_jti
    ON auth_refresh_sessions (jti);

CREATE INDEX ix_auth_refresh_sessions_user_expires_jti
    ON auth_refresh_sessions (user_id, expires_at, jti);

CREATE INDEX ix_auth_refresh_sessions_family
    ON auth_refresh_sessions (user_id, family_id);

CREATE TABLE auth_recovery_tokens (
    email_hash CHAR(64)     NOT NULL,
    token_hash CHAR(64)     NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_auth_recovery_tokens PRIMARY KEY (email_hash)
);

CREATE INDEX ix_auth_recovery_tokens_expires
    ON auth_recovery_tokens (expires_at);

CREATE TABLE auth_mfa_login_challenges (
    user_id    UUID         NOT NULL,
    jti        VARCHAR(64)  NOT NULL,
    token_hash CHAR(64)     NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_auth_mfa_login_challenges PRIMARY KEY (user_id, jti)
);

CREATE INDEX ix_auth_mfa_login_challenges_expires
    ON auth_mfa_login_challenges (expires_at);

CREATE TABLE auth_session_cursors (
    cursor_hash CHAR(64)     NOT NULL,
    user_id     UUID         NOT NULL,
    next_jti    VARCHAR(64)  NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL,
    CONSTRAINT pk_auth_session_cursors PRIMARY KEY (cursor_hash)
);

CREATE INDEX ix_auth_session_cursors_expires
    ON auth_session_cursors (expires_at);

CREATE TABLE oauth_revoked_tokens (
    jti        VARCHAR(128) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT pk_oauth_revoked_tokens PRIMARY KEY (jti)
);

CREATE INDEX ix_oauth_revoked_tokens_expires
    ON oauth_revoked_tokens (expires_at);
