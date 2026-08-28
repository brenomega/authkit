package io.github.brenomega.authkit.service.spi;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Persists server-side authentication state whose possession must be revocable.
 *
 * <p>Implementations must never persist raw refresh, recovery, or MFA challenge
 * secrets. Secret comparisons are expected to avoid data-dependent timing. All
 * expiration arguments are relative lifetimes measured from the call.</p>
 *
 * <p>The default rotation and recovery-consumption methods preserve source
 * compatibility only; they are composed from multiple operations and therefore
 * cannot provide concurrency safety. Production adapters must override them with
 * an atomic compare-and-delete or compare-and-replace operation. AuthKit's Redis
 * and JDBC adapters do so.</p>
 */
public interface TokenStorage {

    /**
     * Creates a refresh-token session.
     *
     * <p>The {@code userId}, {@code jti}, and identity encoded in
     * {@code rawToken} must describe the same session. Storing a token also
     * establishes the active member of its rotation family.</p>
     *
     * @param durationDays lifetime of the session in days
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
     * Tests whether a raw refresh token identifies the active stored session.
     *
     * @return {@code true} only when the session exists, has not expired, and the
     *         supplied secret matches
     */
    boolean validateToken(String userId, String jti, String rawToken);

    /**
     * Tests whether a session identifier is active for access-token binding.
     *
     * <p>This intentionally does not validate a raw refresh-token secret. It is used
     * after JWT signature, issuer, audience, and expiry validation to ensure the JWT
     * {@code jti} is still present in the server-side session store. The default
     * denies access so an adapter that does not support this check cannot silently
     * weaken revocation.</p>
     */
    default boolean isSessionActive(String userId, String jti) {
        return false;
    }

    /**
     * Replaces a refresh token while preserving its rotation family.
     *
     * <p>A concurrency-safe implementation performs validation, removal of the
     * current token, and insertion of the successor atomically. Reuse of a token
     * whose family has already advanced is treated as replay: the active family
     * member is revoked and {@code TokenFamilyCompromisedException} is raised.
     * A simple invalid or expired token returns {@code false}.</p>
     *
     * @param durationDays lifetime of the replacement session in days
     * @return {@code true} if this call performed the rotation
     * @throws io.github.brenomega.authkit.exception.TokenFamilyCompromisedException
     *         if reuse of an advanced family is detected
     */
    boolean rotateRefreshToken(String userId, String currentJti, String currentRawToken,
                               String nextJti, String nextRawToken, long durationDays);

    /**
     * Lists active sessions without exposing internal token identifiers.
     *
     * <p>The limit is between 1 and 100. A continuation cursor is opaque,
     * short-lived, bound to the user, and consumed when used; callers must not
     * infer ordering or snapshot consistency from a page.</p>
     *
     * @param cursor opaque continuation cursor, or {@code null} for the first page
     * @throws io.github.brenomega.authkit.exception.InvalidSessionCursorException
     *         if the limit or cursor is invalid, expired, reused, or belongs to
     *         another user
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
     * Revokes every refresh-token session owned by the user.
     */
    void revokeAllSessions(String userId);

    /**
     * Revokes all sessions except the identified current session.
     *
     * <p>This operation is used after a password change so the authenticated
     * session can continue while every other refresh credential is invalidated.</p>
     */
    void revokeOtherSessions(String userId, String currentJti);

    /**
     * Stores the current password-recovery token for a normalized email address.
     *
     * <p>Storing another token for the same address replaces the previous one.</p>
     *
     * @param email           the user's email (used as key part)
     * @param rawToken        the raw high-entropy token
     * @param durationMinutes the token expiration in minutes
     */
    void storeRecoveryToken(String email, String rawToken, long durationMinutes);

    /**
     * Tests a recovery token without consuming it.
     *
     * @param email    the user's email
     * @param rawToken the token to validate
     * @return true if valid and not expired
     */
    boolean validateRecoveryToken(String email, String rawToken);

    /**
     * Validates and consumes a recovery token exactly once.
     *
     * <p>Production implementations must make the comparison and deletion one
     * atomic operation so concurrent callers cannot both succeed.</p>
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
     * Invalidates the current recovery token for the normalized email address.
     *
     * @param email the user's email
     */
    void revokeRecoveryToken(String email);

    /** Revokes only when the currently stored token matches the supplied raw value. */
    default void revokeRecoveryTokenIfMatches(String email, String rawToken) {
        consumeRecoveryToken(email, rawToken);
    }

    /**
     * Stores a short-lived login challenge without creating a user session.
     *
     * @param durationMinutes challenge lifetime in minutes
     * @throws UnsupportedOperationException if the adapter does not support MFA
     *         challenges
     */
    default void storeMfaChallenge(String userId, String jti, String rawToken, long durationMinutes) {
        throw new UnsupportedOperationException("MFA challenge storage is not configured");
    }

    /**
     * Validates and consumes an MFA login challenge exactly once.
     *
     * <p>The implementation must combine comparison, expiration enforcement, and
     * deletion atomically.</p>
     *
     * @return {@code true} only for the caller that consumed a matching,
     *         unexpired challenge
     * @throws UnsupportedOperationException if the adapter does not support MFA
     *         challenges
     */
    default boolean consumeMfaChallenge(String userId, String jti, String rawToken) {
        throw new UnsupportedOperationException("MFA challenge storage is not configured");
    }
}
