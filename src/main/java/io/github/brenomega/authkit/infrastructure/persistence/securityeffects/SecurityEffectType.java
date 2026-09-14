package io.github.brenomega.authkit.infrastructure.persistence.securityeffects;

/** External security effects whose durable intent is committed with the SQL mutation. */
public enum SecurityEffectType {
    ACTIVATE_RECOVERY_TOKEN,
    REVOKE_STALE_SESSIONS,
    REVOKE_RECOVERY_TOKEN
}
