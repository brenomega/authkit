-- Durable singleton guard for serialized, one-shot first-administrator bootstrap.
CREATE TABLE authkit_bootstrap_state (
    id            INTEGER     NOT NULL,
    completed_at  TIMESTAMPTZ,
    admin_user_id UUID,
    CONSTRAINT pk_authkit_bootstrap_state PRIMARY KEY (id),
    CONSTRAINT ck_authkit_bootstrap_singleton CHECK (id = 1),
    CONSTRAINT fk_authkit_bootstrap_admin FOREIGN KEY (admin_user_id) REFERENCES users(id),
    CONSTRAINT ck_authkit_bootstrap_completion CHECK (
        (completed_at IS NULL AND admin_user_id IS NULL)
        OR (completed_at IS NOT NULL AND admin_user_id IS NOT NULL)
    )
);

INSERT INTO authkit_bootstrap_state (id, completed_at, admin_user_id)
SELECT 1, CURRENT_TIMESTAMP, id
FROM users
WHERE role = 'PLATFORM_ADMIN'
ORDER BY id
LIMIT 1;

INSERT INTO authkit_bootstrap_state (id, completed_at, admin_user_id)
VALUES (1, NULL, NULL)
ON CONFLICT (id) DO NOTHING;
