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
     * Verifies that a session identifier is still active for access-token binding.
     *
     * <p>This intentionally does not validate a raw refresh-token secret. It is used
     * after JWT signature, issuer, audience, and expiry validation to ensure the JWT
     * {@code jti} is still present in the server-side session store.</p>
     */
    default boolean isSessionActive(String userId, String jti) {
        return false;
    }

    /**
     * Atomically validates the current refresh token, consumes it, and stores the
     * replacement token for rotation/replay resistance.
     */
    default boolean rotateRefreshToken(String userId, String currentJti, String currentRawToken,
                                       String nextJti, String nextRawToken, long durationDays) {
        if (!validateToken(userId, currentJti, currentRawToken)) {
            return false;
        }
        revokeSession(userId, currentJti);
        storeRefreshToken(userId, nextJti, nextRawToken, durationDays);
        return true;
    }

    /**
     * Lists all active session identifiers (JTIs) for a user.
     */
    SessionPage listSessions(String userId, int limit, String cursor);

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
     * Atomically validates and consumes a recovery token.
     *
     * @param email    the user's email
     * @param rawToken the token to validate and consume
     * @return true if the token was valid and was consumed
     */
    default boolean consumeRecoveryToken(String email, String rawToken) {
        if (!validateRecoveryToken(email, rawToken)) {
            return false;
        }
        revokeRecoveryToken(email);
        return true;
    }

    /**
     * Immediately invalidates the recovery token for the given email.
     *
     * @param email the user's email
     */
    void revokeRecoveryToken(String email);

    default void storeMfaChallenge(String userId, String jti, String rawToken, long durationMinutes) {
        throw new UnsupportedOperationException("MFA challenge storage is not configured");
    }

    default boolean consumeMfaChallenge(String userId, String jti, String rawToken) {
        throw new UnsupportedOperationException("MFA challenge storage is not configured");
    }
}
