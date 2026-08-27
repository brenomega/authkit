-- Runtime DML is separated from schema ownership and retention DELETE authority.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authkit_runtime') THEN
        CREATE ROLE authkit_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA ${flyway:defaultSchema} TO authkit_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${flyway:defaultSchema} TO authkit_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ${flyway:defaultSchema} TO authkit_runtime;

-- Audit datasets are append-only for the application. Retention deletion is
-- available exclusively through the SECURITY DEFINER functions from V18.
REVOKE UPDATE, DELETE ON security_events, consent_events, retention_purge_log FROM authkit_runtime;
REVOKE INSERT ON retention_purge_log FROM authkit_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA ${flyway:defaultSchema}
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO authkit_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA ${flyway:defaultSchema}
    GRANT USAGE, SELECT ON SEQUENCES TO authkit_runtime;
