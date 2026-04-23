package io.github.brenomega.authkit.service.spi;

/**
 * Service Provider Interface for token storage boundaries.
 */
public interface TokenStorage {

    /**
     * Stores a generated refresh token for the user.
     */
    void storeRefreshToken(String userId, String rawToken, long durationDays);

    /**
     * Constant-time verification of a raw token against the persistence layer.
     */
    boolean validateToken(String userId, String rawToken);

    /**
     * Immediately destroys the active refresh tokens for the user context.
     */
    void revokeTokens(String userId);

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
