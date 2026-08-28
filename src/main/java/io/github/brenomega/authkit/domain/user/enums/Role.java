package io.github.brenomega.authkit.domain.user.enums;

/**
 * Represents the mutually exclusive authorization role loaded from account state.
 *
 * <p>Roles are loaded from the database on first-party requests rather than
 * trusted from JWT claims. {@code OWNER} currently has self-service access only;
 * it is reserved for future ownership flows and is not an administrative role.</p>
 *
 * @see io.github.brenomega.authkit.infrastructure.security.SecurityUser
 */
public enum Role {

    USER,

    /** Reserved tenant-owner identity with no current admin-plane access. */
    OWNER,

    /** Tenant administrator scoped to users and OAuth clients in one tenant. */
    TENANT_ADMIN,

    /** System administrator with full platform access. */
    ADMIN
}
