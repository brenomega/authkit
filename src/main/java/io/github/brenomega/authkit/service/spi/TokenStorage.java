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
}
