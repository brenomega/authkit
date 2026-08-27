-- GA social/OIDC relying-party state. Providers are instance-global; identities
-- are keyed by the immutable OIDC (issuer, subject) pair.

CREATE TABLE social_identity_providers (
    id                      UUID         NOT NULL,
    provider_key            VARCHAR(64)  NOT NULL,
    display_name            VARCHAR(120) NOT NULL,
    provider_type           VARCHAR(32)  NOT NULL,
    issuer                  VARCHAR(512) NOT NULL,
    client_id               VARCHAR(255) NOT NULL,
    encrypted_client_secret TEXT         NOT NULL,
    scopes                  VARCHAR(512) NOT NULL,
    client_auth_method      VARCHAR(32)  NOT NULL,
    enabled                 BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ  NOT NULL,
    updated_at              TIMESTAMPTZ  NOT NULL,
    disabled_at             TIMESTAMPTZ,

    CONSTRAINT pk_social_identity_providers PRIMARY KEY (id),
    CONSTRAINT uq_social_identity_providers_key UNIQUE (provider_key),
    CONSTRAINT uq_social_identity_providers_issuer UNIQUE (issuer),
    CONSTRAINT ck_social_identity_provider_type
        CHECK (provider_type IN ('GOOGLE', 'GENERIC_OIDC', 'GOVBR_EXPERIMENTAL')),
    CONSTRAINT ck_social_identity_client_auth
        CHECK (client_auth_method IN ('CLIENT_SECRET_BASIC', 'CLIENT_SECRET_POST')),
    CONSTRAINT ck_social_identity_https_issuer CHECK (issuer LIKE 'https://%')
);

CREATE TABLE social_identities (
    id                  UUID         NOT NULL,
    user_id             UUID         NOT NULL,
    tenant_id           UUID         NOT NULL,
    provider_id         UUID         NOT NULL,
    issuer              VARCHAR(512) NOT NULL,
    subject             VARCHAR(255) NOT NULL,
    email_at_link       VARCHAR(255),
    email_verified      BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ  NOT NULL,
    last_login_at       TIMESTAMPTZ,

    CONSTRAINT pk_social_identities PRIMARY KEY (id),
    CONSTRAINT fk_social_identities_user FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT fk_social_identities_provider FOREIGN KEY (provider_id) REFERENCES social_identity_providers (id),
    CONSTRAINT uq_social_identities_issuer_subject UNIQUE (issuer, subject),
    CONSTRAINT uq_social_identities_user_provider UNIQUE (user_id, provider_id)
);

CREATE INDEX idx_social_identities_user ON social_identities (user_id, created_at DESC);

CREATE TABLE social_login_transactions (
    id                  UUID         NOT NULL,
    state_hash          VARCHAR(64)  NOT NULL,
    provider_id         UUID         NOT NULL,
    purpose             VARCHAR(16)  NOT NULL,
    user_id             UUID,
    nonce               VARCHAR(128) NOT NULL,
    encrypted_verifier  TEXT         NOT NULL,
    terms_accepted      BOOLEAN      NOT NULL DEFAULT FALSE,
    privacy_accepted    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ  NOT NULL,
    expires_at          TIMESTAMPTZ  NOT NULL,
    consumed_at         TIMESTAMPTZ,

    CONSTRAINT pk_social_login_transactions PRIMARY KEY (id),
    CONSTRAINT uq_social_login_transactions_state UNIQUE (state_hash),
    CONSTRAINT fk_social_login_transactions_provider FOREIGN KEY (provider_id) REFERENCES social_identity_providers (id),
    CONSTRAINT fk_social_login_transactions_user FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT ck_social_login_transaction_purpose CHECK (purpose IN ('LOGIN', 'LINK')),
    CONSTRAINT ck_social_login_transaction_user
        CHECK ((purpose = 'LOGIN' AND user_id IS NULL) OR (purpose = 'LINK' AND user_id IS NOT NULL))
);

CREATE INDEX idx_social_login_transactions_expiry ON social_login_transactions (expires_at);
