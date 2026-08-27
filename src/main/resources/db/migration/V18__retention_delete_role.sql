-- Audit DELETE is available only through narrowly scoped SECURITY DEFINER
-- functions granted to a non-login retention role. The application runtime
-- login must not own these tables and must never be a member of this role.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_retention') THEN
        CREATE ROLE authkit_retention NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END
$$;

REVOKE DELETE ON security_events, consent_events FROM PUBLIC;

CREATE TABLE retention_purge_log (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    dataset VARCHAR(64) NOT NULL,
    deleted_count BIGINT NOT NULL CHECK (deleted_count >= 0),
    database_actor VARCHAR(128) NOT NULL DEFAULT CURRENT_USER,
    CONSTRAINT pk_retention_purge_log PRIMARY KEY (id)
);

CREATE TRIGGER trg_retention_purge_log_prevent_update
    BEFORE UPDATE ON retention_purge_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_row_update();

REVOKE UPDATE, DELETE ON retention_purge_log FROM PUBLIC;

CREATE OR REPLACE FUNCTION retention_purge_security_events(event_ids UUID[])
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ${flyway:defaultSchema}
AS $$
DECLARE
    deleted_count BIGINT;
BEGIN
    DELETE FROM security_events WHERE id = ANY(event_ids);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    INSERT INTO retention_purge_log(dataset, deleted_count)
    VALUES ('security_events_by_id', deleted_count);
    RETURN deleted_count;
END
$$;

CREATE OR REPLACE FUNCTION retention_purge_security_events_for_users(user_ids UUID[])
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ${flyway:defaultSchema}
AS $$
DECLARE
    deleted_count BIGINT;
BEGIN
    DELETE FROM security_events
    WHERE actor_user_id = ANY(user_ids) OR target_user_id = ANY(user_ids);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    INSERT INTO retention_purge_log(dataset, deleted_count)
    VALUES ('security_events_by_user', deleted_count);
    RETURN deleted_count;
END
$$;

CREATE OR REPLACE FUNCTION retention_purge_consent_events_for_users(user_ids UUID[])
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, ${flyway:defaultSchema}
AS $$
DECLARE
    deleted_count BIGINT;
BEGIN
    DELETE FROM consent_events WHERE user_id = ANY(user_ids);
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    INSERT INTO retention_purge_log(dataset, deleted_count)
    VALUES ('consent_events_by_user', deleted_count);
    RETURN deleted_count;
END
$$;

REVOKE ALL ON FUNCTION retention_purge_security_events(UUID[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION retention_purge_security_events_for_users(UUID[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION retention_purge_consent_events_for_users(UUID[]) FROM PUBLIC;

GRANT USAGE ON SCHEMA ${flyway:defaultSchema} TO authkit_retention;
GRANT EXECUTE ON FUNCTION retention_purge_security_events(UUID[]) TO authkit_retention;
GRANT EXECUTE ON FUNCTION retention_purge_security_events_for_users(UUID[]) TO authkit_retention;
GRANT EXECUTE ON FUNCTION retention_purge_consent_events_for_users(UUID[]) TO authkit_retention;
