-- Phase 8: passkeys/WebAuthn, OAuth2/OIDC provider state, and admin policy-plane data.

CREATE TABLE passkey_credentials (
    id                  UUID         NOT NULL,
    user_id             UUID         NOT NULL,
    tenant_id           UUID         NOT NULL,
    credential_id       VARCHAR(512) NOT NULL,
    public_key_cose     TEXT         NOT NULL,
    signature_count     BIGINT       NOT NULL DEFAULT 0,
    transports          VARCHAR(255),
    label               VARCHAR(100),
    discoverable        BOOLEAN      NOT NULL DEFAULT FALSE,
    backup_eligible     BOOLEAN      NOT NULL DEFAULT FALSE,
    backed_up           BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ  NOT NULL,
    last_used_at        TIMESTAMPTZ,
    disabled_at         TIMESTAMPTZ,

    CONSTRAINT pk_passkey_credentials PRIMARY KEY (id),
    CONSTRAINT fk_passkey_credentials_user
        FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE UNIQUE INDEX uq_passkey_credentials_credential_id
    ON passkey_credentials (credential_id);

CREATE INDEX idx_passkey_credentials_user_active
    ON passkey_credentials (user_id, created_at DESC)
    WHERE disabled_at IS NULL;

CREATE INDEX idx_passkey_credentials_tenant
    ON passkey_credentials (tenant_id, created_at DESC);

CREATE TABLE passkey_challenges (
    id             UUID         NOT NULL,
    ceremony_type  VARCHAR(32)  NOT NULL,
    user_id        UUID,
    request_json   TEXT         NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL,
    expires_at     TIMESTAMPTZ  NOT NULL,
    consumed_at    TIMESTAMPTZ,

    CONSTRAINT pk_passkey_challenges PRIMARY KEY (id),
    CONSTRAINT ck_passkey_challenges_type
        CHECK (ceremony_type IN ('REGISTRATION', 'ASSERTION')),
    CONSTRAINT fk_passkey_challenges_user
        FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE INDEX idx_passkey_challenges_expires
    ON passkey_challenges (expires_at);

CREATE TABLE oauth_clients (
    id                 UUID          NOT NULL,
    tenant_id          UUID,
    client_id          VARCHAR(128)  NOT NULL,
    client_secret_hash VARCHAR(255),
    public_client      BOOLEAN       NOT NULL DEFAULT TRUE,
    display_name       VARCHAR(120)  NOT NULL,
    redirect_uris      TEXT          NOT NULL,
    scopes             TEXT          NOT NULL,
    require_pkce       BOOLEAN       NOT NULL DEFAULT TRUE,
    enabled            BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ   NOT NULL,
    updated_at         TIMESTAMPTZ   NOT NULL,
    disabled_at        TIMESTAMPTZ,

    CONSTRAINT pk_oauth_clients PRIMARY KEY (id),
    CONSTRAINT uq_oauth_clients_client_id UNIQUE (client_id),
    CONSTRAINT ck_oauth_clients_secret
        CHECK (public_client = TRUE OR client_secret_hash IS NOT NULL)
);

CREATE INDEX idx_oauth_clients_tenant
    ON oauth_clients (tenant_id, created_at DESC)
    WHERE tenant_id IS NOT NULL;

CREATE TABLE oauth_consents (
    id          UUID         NOT NULL,
    user_id     UUID         NOT NULL,
    tenant_id   UUID         NOT NULL,
    client_id   VARCHAR(128) NOT NULL,
    scopes      TEXT         NOT NULL,
    granted_at  TIMESTAMPTZ  NOT NULL,
    revoked_at  TIMESTAMPTZ,

    CONSTRAINT pk_oauth_consents PRIMARY KEY (id),
    CONSTRAINT fk_oauth_consents_user
        FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT fk_oauth_consents_client
        FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id)
);

CREATE UNIQUE INDEX uq_oauth_consents_active_user_client
    ON oauth_consents (user_id, client_id)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_oauth_consents_tenant
    ON oauth_consents (tenant_id, granted_at DESC);

CREATE TABLE oauth_authorization_codes (
    id                  UUID         NOT NULL,
    code_hash           VARCHAR(64)  NOT NULL,
    client_id           VARCHAR(128) NOT NULL,
    user_id             UUID         NOT NULL,
    tenant_id           UUID         NOT NULL,
    redirect_uri        VARCHAR(512) NOT NULL,
    scopes              TEXT         NOT NULL,
    amr                 VARCHAR(255) NOT NULL,
    code_challenge      VARCHAR(128) NOT NULL,
    code_challenge_method VARCHAR(16) NOT NULL,
    nonce               VARCHAR(255),
    created_at          TIMESTAMPTZ  NOT NULL,
    expires_at          TIMESTAMPTZ  NOT NULL,
    consumed_at         TIMESTAMPTZ,

    CONSTRAINT pk_oauth_authorization_codes PRIMARY KEY (id),
    CONSTRAINT uq_oauth_authorization_codes_code_hash UNIQUE (code_hash),
    CONSTRAINT fk_oauth_authorization_codes_user
        FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT ck_oauth_authorization_code_method
        CHECK (code_challenge_method = 'S256')
);

CREATE INDEX idx_oauth_authorization_codes_expiry
    ON oauth_authorization_codes (expires_at);

CREATE INDEX idx_oauth_authorization_codes_client
    ON oauth_authorization_codes (client_id, created_at DESC);
