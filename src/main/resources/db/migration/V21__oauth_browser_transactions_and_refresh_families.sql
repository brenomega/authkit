CREATE TABLE oauth_authorization_transactions (
    id                    UUID         NOT NULL,
    token_hash            VARCHAR(64)  NOT NULL,
    client_id             VARCHAR(128) NOT NULL,
    redirect_uri          VARCHAR(512) NOT NULL,
    scopes                TEXT         NOT NULL,
    state                 VARCHAR(255) NOT NULL,
    nonce                 VARCHAR(255),
    code_challenge        VARCHAR(128) NOT NULL,
    code_challenge_method VARCHAR(16)  NOT NULL,
    created_at            TIMESTAMPTZ  NOT NULL,
    expires_at            TIMESTAMPTZ  NOT NULL,
    consumed_at           TIMESTAMPTZ,
    CONSTRAINT pk_oauth_authorization_transactions PRIMARY KEY (id),
    CONSTRAINT uq_oauth_authorization_transactions_hash UNIQUE (token_hash),
    CONSTRAINT fk_oauth_authorization_transactions_client FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id),
    CONSTRAINT ck_oauth_authorization_transactions_method CHECK (code_challenge_method = 'S256')
);
CREATE INDEX idx_oauth_authorization_transactions_expiry ON oauth_authorization_transactions (expires_at);

CREATE TABLE oauth_refresh_token_families (
    id                UUID         NOT NULL,
    user_id           UUID         NOT NULL,
    client_id         VARCHAR(128) NOT NULL,
    scopes            TEXT         NOT NULL,
    amr               VARCHAR(255) NOT NULL,
    active_token_hash VARCHAR(64)  NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL,
    expires_at        TIMESTAMPTZ  NOT NULL,
    revoked_at        TIMESTAMPTZ,
    compromised_at    TIMESTAMPTZ,
    CONSTRAINT pk_oauth_refresh_token_families PRIMARY KEY (id),
    CONSTRAINT fk_oauth_refresh_family_user FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT fk_oauth_refresh_family_client FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id)
);
CREATE INDEX idx_oauth_refresh_families_user ON oauth_refresh_token_families (user_id, created_at DESC);

CREATE TABLE oauth_refresh_tokens (
    id                  UUID        NOT NULL,
    token_hash          VARCHAR(64) NOT NULL,
    family_id           UUID        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    consumed_at         TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    replaced_token_hash VARCHAR(64),
    CONSTRAINT pk_oauth_refresh_tokens PRIMARY KEY (id),
    CONSTRAINT uq_oauth_refresh_tokens_hash UNIQUE (token_hash),
    CONSTRAINT fk_oauth_refresh_tokens_family FOREIGN KEY (family_id) REFERENCES oauth_refresh_token_families (id) ON DELETE CASCADE
);
CREATE INDEX idx_oauth_refresh_tokens_family ON oauth_refresh_tokens (family_id, created_at DESC);
CREATE INDEX idx_oauth_refresh_tokens_expiry ON oauth_refresh_tokens (expires_at);
