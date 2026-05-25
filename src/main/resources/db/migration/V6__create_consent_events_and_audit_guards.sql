-- Append-only consent history and database-level update guards for audit records.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE consent_events (
    id                     UUID         NOT NULL,
    user_id                UUID         NOT NULL,
    tenant_id              UUID         NOT NULL,
    terms_version          VARCHAR(64)  NOT NULL,
    privacy_policy_version VARCHAR(64)  NOT NULL,
    lawful_basis           VARCHAR(64)  NOT NULL,
    accepted_at            TIMESTAMPTZ  NOT NULL,
    recorded_at            TIMESTAMPTZ  NOT NULL,
    event_hash             VARCHAR(64)  NOT NULL,

    CONSTRAINT pk_consent_events PRIMARY KEY (id),
    CONSTRAINT ck_consent_events_lawful_basis
        CHECK (lawful_basis IN ('consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interests'))
);

CREATE INDEX idx_consent_events_user
    ON consent_events (user_id, accepted_at DESC);

CREATE INDEX idx_consent_events_tenant
    ON consent_events (tenant_id, accepted_at DESC);

CREATE UNIQUE INDEX uq_consent_events_event_hash
    ON consent_events (event_hash);

CREATE UNIQUE INDEX uq_security_events_event_hash
    ON security_events (event_hash);

INSERT INTO consent_events (
    id,
    user_id,
    tenant_id,
    terms_version,
    privacy_policy_version,
    lawful_basis,
    accepted_at,
    recorded_at,
    event_hash
)
SELECT
    gen_random_uuid(),
    id,
    tenant_id,
    terms_version,
    privacy_policy_version,
    lawful_basis,
    consent_accepted_at,
    CURRENT_TIMESTAMP,
    encode(
        digest(
            id::text || '|' || tenant_id::text || '|' || terms_version || '|' ||
            privacy_policy_version || '|' || lawful_basis || '|' ||
            consent_accepted_at::text,
            'sha256'),
        'hex')
FROM users
WHERE terms_accepted = TRUE
  AND privacy_policy_accepted = TRUE
  AND consent_accepted_at IS NOT NULL;

CREATE OR REPLACE FUNCTION prevent_audit_row_update()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit records are append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_security_events_prevent_update
    BEFORE UPDATE ON security_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_row_update();

CREATE TRIGGER trg_consent_events_prevent_update
    BEFORE UPDATE ON consent_events
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_row_update();
