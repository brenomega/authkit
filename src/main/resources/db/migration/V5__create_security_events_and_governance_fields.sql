-- Durable security events and account governance support for Phases 6 and 7.

ALTER TABLE users
    ADD COLUMN terms_version VARCHAR(64) NOT NULL DEFAULT 'terms-v1',
    ADD COLUMN privacy_policy_version VARCHAR(64) NOT NULL DEFAULT 'privacy-v1',
    ADD COLUMN consent_accepted_at TIMESTAMPTZ,
    ADD COLUMN lawful_basis VARCHAR(64) NOT NULL DEFAULT 'consent',
    ADD COLUMN deletion_requested_at TIMESTAMPTZ,
    ADD COLUMN deleted_at TIMESTAMPTZ,
    ADD COLUMN anonymized_at TIMESTAMPTZ;

UPDATE users
SET consent_accepted_at = CURRENT_TIMESTAMP
WHERE terms_accepted = TRUE
  AND privacy_policy_accepted = TRUE
  AND consent_accepted_at IS NULL;

CREATE TABLE security_events (
    id               UUID          NOT NULL,
    occurred_at      TIMESTAMPTZ   NOT NULL,
    event_type       VARCHAR(80)   NOT NULL,
    outcome          VARCHAR(20)   NOT NULL,
    severity         VARCHAR(20)   NOT NULL,
    actor_user_id    UUID,
    target_user_id   UUID,
    tenant_id        UUID,
    email_hash       VARCHAR(64),
    email_masked     VARCHAR(320),
    client_ip_hash   VARCHAR(64),
    client_ip_masked VARCHAR(80),
    user_agent_hash  VARCHAR(64),
    request_method   VARCHAR(16),
    request_path     VARCHAR(512),
    reason           VARCHAR(120),
    metadata_json    TEXT,
    event_hash       VARCHAR(64)   NOT NULL,

    CONSTRAINT pk_security_events PRIMARY KEY (id),
    CONSTRAINT ck_security_events_outcome
        CHECK (outcome IN ('SUCCESS', 'FAILURE', 'DENIED', 'INFO')),
    CONSTRAINT ck_security_events_severity
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

CREATE INDEX idx_security_events_occurred_at
    ON security_events (occurred_at DESC);

CREATE INDEX idx_security_events_type_occurred_at
    ON security_events (event_type, occurred_at DESC);

CREATE INDEX idx_security_events_actor_user
    ON security_events (actor_user_id, occurred_at DESC)
    WHERE actor_user_id IS NOT NULL;

CREATE INDEX idx_security_events_target_user
    ON security_events (target_user_id, occurred_at DESC)
    WHERE target_user_id IS NOT NULL;

CREATE INDEX idx_security_events_tenant
    ON security_events (tenant_id, occurred_at DESC)
    WHERE tenant_id IS NOT NULL;

CREATE INDEX idx_security_events_severity
    ON security_events (severity, occurred_at DESC);
