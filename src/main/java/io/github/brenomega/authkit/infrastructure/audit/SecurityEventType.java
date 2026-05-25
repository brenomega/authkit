package io.github.brenomega.authkit.infrastructure.audit;

/**
 * Durable security event names used for incident response and compliance review.
 */
public enum SecurityEventType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    ACCOUNT_LOCKED,
    PASSWORD_RESET_REQUESTED,
    PASSWORD_RESET_COMPLETED,
    PASSWORD_RESET_FAILED,
    REFRESH_TOKEN_ROTATED,
    REFRESH_TOKEN_REUSE_DETECTED,
    REFRESH_TOKEN_FAILED,
    LOGOUT,
    LOGOUT_ALL,
    PASSWORD_CHANGED,
    EMAIL_VERIFIED,
    MFA_CHANGED,
    ACCOUNT_DELETION_REQUESTED,
    ACCOUNT_ANONYMIZED,
    DATA_EXPORT_REQUESTED
}
