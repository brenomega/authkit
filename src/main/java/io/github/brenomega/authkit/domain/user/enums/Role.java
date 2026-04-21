package io.github.brenomega.authkit.domain.user.enums;

/**
 * Enumeration of user roles within the authentication system (DT 3.2.9).
 *
 * <p>Roles are persisted as strings in the database via
 * {@code @Enumerated(EnumType.STRING)} and converted to Spring Security
 * {@code GrantedAuthority} instances with the {@code ROLE_} prefix by the
 * security layer.</p>
 *
 * @see io.github.brenomega.authkit.infrastructure.security.SecurityUser
 */
public enum Role {

    /** Standard end-user with basic access rights. */
    USER,

    /** Tenant owner with elevated data-management permissions. */
    OWNER,

    /** System administrator with full platform access. */
    ADMIN
}
