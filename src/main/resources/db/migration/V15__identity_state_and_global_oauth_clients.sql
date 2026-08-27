-- AuthKit v0.1 identity model: personal partitions, two roles, durable states.

ALTER TABLE users
    ADD COLUMN account_state VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN suspended_at TIMESTAMPTZ,
    ADD COLUMN suspension_reason VARCHAR(500);

UPDATE users
SET account_state = CASE
    WHEN anonymized_at IS NOT NULL OR deleted_at IS NOT NULL THEN 'ANONYMIZED'
    WHEN deletion_requested_at IS NOT NULL THEN 'DELETION_PENDING'
    ELSE 'ACTIVE'
END;

-- ADMIN is the only legacy role with instance-wide authority. Tenant-oriented
-- roles are deliberately reduced to USER rather than silently escalated.
UPDATE users SET role = 'PLATFORM_ADMIN' WHERE role = 'ADMIN';
UPDATE users SET role = 'USER' WHERE role IN ('OWNER', 'TENANT_ADMIN');

ALTER TABLE users
    ALTER COLUMN password DROP NOT NULL,
    DROP COLUMN phone,
    ADD CONSTRAINT ck_users_role CHECK (role IN ('USER', 'PLATFORM_ADMIN')),
    ADD CONSTRAINT ck_users_account_state
        CHECK (account_state IN ('ACTIVE', 'SUSPENDED', 'DELETION_PENDING', 'ANONYMIZED')),
    ADD CONSTRAINT ck_users_suspension_fields CHECK (
        (account_state = 'SUSPENDED' AND suspended_at IS NOT NULL AND suspension_reason IS NOT NULL)
        OR account_state <> 'SUSPENDED'
    );

DROP INDEX IF EXISTS idx_oauth_clients_tenant;
ALTER TABLE oauth_clients DROP COLUMN tenant_id;

DROP INDEX IF EXISTS idx_users_role_active;
CREATE INDEX idx_users_role_state ON users (role, account_state);
CREATE INDEX idx_users_account_state ON users (account_state);

-- Serialize destructive transitions of platform administrators and reject the
-- final one at the database boundary, including concurrent requests.
CREATE OR REPLACE FUNCTION authkit_protect_last_platform_admin()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.role = 'PLATFORM_ADMIN' AND OLD.account_state = 'ACTIVE'
       AND (TG_OP = 'DELETE'
            OR NEW.role <> 'PLATFORM_ADMIN'
            OR NEW.account_state <> 'ACTIVE') THEN
        PERFORM pg_advisory_xact_lock(104857601);
        IF (SELECT count(*) FROM users
            WHERE role = 'PLATFORM_ADMIN'
              AND account_state = 'ACTIVE'
              AND id <> OLD.id) = 0 THEN
            RAISE EXCEPTION 'cannot remove the last active platform administrator'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER trg_protect_last_platform_admin
BEFORE UPDATE OR DELETE ON users
FOR EACH ROW EXECUTE FUNCTION authkit_protect_last_platform_admin();
