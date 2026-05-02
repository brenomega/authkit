package io.github.brenomega.authkit.service.spi;

/**
 * Service Provider Interface for token storage boundaries.
 */
public interface TokenStorage {

    /**
     * Stores a generated refresh token for the user with an explicit session identifier (JTI).
     */
    void storeRefreshToken(String userId, String jti, String rawToken, long durationDays);

    /**
     * Constant-time verification of a raw token against the persistence layer using JTI.
     */
    boolean validateToken(String userId, String jti, String rawToken);

    /**
     * Lists all active session identifiers (JTIs) for a user.
     */
    java.util.List<String> listSessions(String userId);

    /**
     * Revokes a specific session by its JTI.
     */
    void revokeSession(String userId, String jti);

    /**
     * Immediately destroys all active refresh tokens for the user context.
     */
    void revokeAllSessions(String userId);

    /**
     * Revokes all sessions except the one specified by currentJti.
     * Hardening step for password changes.
     */
    void revokeOtherSessions(String userId, String currentJti);

    /**
     * Stores a generated password recovery token.
     *
     * @param email           the user's email (used as key part)
     * @param rawToken        the raw high-entropy token
     * @param durationMinutes the token expiration in minutes
     */
    void storeRecoveryToken(String email, String rawToken, long durationMinutes);

    /**
     * Constant-time verification of a recovery token.
     *
     * @param email    the user's email
     * @param rawToken the token to validate
     * @return true if valid and not expired
     */
    boolean validateRecoveryToken(String email, String rawToken);

    /**
     * Immediately invalidates the recovery token for the given email.
     *
     * @param email the user's email
     */
    void revokeRecoveryToken(String email);
}
