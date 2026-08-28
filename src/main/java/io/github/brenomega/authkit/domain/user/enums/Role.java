package io.github.brenomega.authkit.domain.user.enums;

/**
 * Represents the mutually exclusive authorization role loaded from account state.
 *
 * <p>Roles are loaded from the database on first-party requests rather than
 * trusted from JWT claims.</p>
 *
 * @see io.github.brenomega.authkit.infrastructure.security.SecurityUser
 */
public enum Role {

    USER,

    /** Instance-wide administrative role. */
    PLATFORM_ADMIN
}
