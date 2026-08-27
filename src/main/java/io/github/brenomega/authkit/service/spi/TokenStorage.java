package io.github.brenomega.authkit.service.spi;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Service Provider Interface for token storage boundaries.
 */
public interface TokenStorage {

    /**
     * Stores a generated refresh token for the user with an explicit session identifier (JTI).
     */
    default void storeRefreshToken(String userId, String jti, String rawToken, long durationDays) {
        Instant now = Instant.now();
        storeRefreshToken(userId, jti, rawToken, durationDays, new SessionMetadata(
                UUID.randomUUID().toString(), jti, now, now,
                now.plusSeconds(Math.multiplyExact(durationDays, 86_400L)),
                List.of(), "Unknown client", null, "unknown", "unknown"));
    }

    /** Stores a refresh token and its public, privacy-preserving session metadata atomically. */
    void storeRefreshToken(String userId, String jti, String rawToken, long durationDays,
                           SessionMetadata metadata);

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
    boolean rotateRefreshToken(String userId, String currentJti, String currentRawToken,
                               String nextJti, String nextRawToken, long durationDays);

    /**
     * Lists active sessions without exposing internal token identifiers.
     */
    SessionPage listSessions(String userId, int limit, String cursor);

    /**
     * Revokes a specific session by its opaque public identifier.
     */
    void revokeSession(String userId, String publicSessionId);

    /** Revokes by internal JTI for trusted token-processing code only. */
    void revokeSessionByJti(String userId, String jti);

    /** Records bounded activity without writing more frequently than the configured interval. */
    void touchSession(String userId, String jti, Instant seenAt, String maskedIp, long throttleSeconds);

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
    boolean consumeRecoveryToken(String email, String rawToken);

    /**
     * Atomically reserves a valid recovery token for one database transaction.
     * A failed transaction can release the claim; completion consumes it.
     */
    boolean claimRecoveryToken(String email, String rawToken, String claimId, long claimTtlSeconds);

    /** Completes a previously acquired recovery-token claim. */
    void completeRecoveryTokenClaim(String email, String claimId);

    /** Releases a previously acquired claim without consuming the token. */
    void releaseRecoveryTokenClaim(String email, String claimId);

    /**
     * Immediately invalidates the recovery token for the given email.
     *
     * @param email the user's email
     */
    void revokeRecoveryToken(String email);

    /** Revokes only when the currently stored token matches the supplied raw value. */
    default void revokeRecoveryTokenIfMatches(String email, String rawToken) {
        consumeRecoveryToken(email, rawToken);
    }

    default void storeMfaChallenge(String userId, String jti, String rawToken, long durationMinutes) {
        throw new UnsupportedOperationException("MFA challenge storage is not configured");
    }

    default boolean consumeMfaChallenge(String userId, String jti, String rawToken) {
        throw new UnsupportedOperationException("MFA challenge storage is not configured");
    }
}
