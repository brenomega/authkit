package io.github.brenomega.authkit.domain.user.enums;

/** Represents the authentication and lifecycle state of an account. */
public enum AccountState {
    ACTIVE,
    SUSPENDED,
    DELETION_PENDING,
    ANONYMIZED
}
