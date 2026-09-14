package io.github.brenomega.authkit.service.spi;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

/**
 * Persists revocable, server-side state for first-party authentication tokens.
 *
 * <p>Implementations must store digests rather than raw refresh, recovery or MFA
 * secrets and compare supplied secrets without data-dependent timing. Relative
 * expiration arguments are measured from the operation. Production adapters are
 * expected to preserve the atomicity requirements stated on rotation,
 * consumption and recovery claims under concurrent access.</p>
 */
public interface TokenStorage {

    /**
     * Creates a refresh session with minimal generated metadata.
     *
     * <p>This compatibility overload cannot describe the requesting device and
     * should not be preferred by request-aware callers.</p>
     *
     * @param durationDays session lifetime in days
     */
    default void storeRefreshToken(String userId, String jti, String rawToken, long durationDays) {
        Instant now = Instant.now();
        storeRefreshToken(userId, jti, rawToken, durationDays, new SessionMetadata(
                UUID.randomUUID().toString(), jti, now, now,
                now.plusSeconds(Math.multiplyExact(durationDays, 86_400L)),
                0, List.of(), "Unknown client", null, "unknown", "unknown"));
    }

    /**
     * Stores a refresh secret, family pointer and public session metadata as one
     * logical session.
     *
     * @param durationDays session lifetime in days
     */
    void storeRefreshToken(String userId, String jti, String rawToken, long durationDays,
                           SessionMetadata metadata);

    /**
     * Validates the secret for an unexpired active refresh session.
     *
     * @return {@code true} only when the session exists and the secret matches
     */
    boolean validateToken(String userId, String jti, String rawToken);

    /**
     * Checks server-side presence of the session bound to an already validated JWT.
     *
     * <p>The fail-closed default prevents an adapter without revocation support
     * from silently accepting access tokens.</p>
     */
    default boolean isSessionActive(String userId, String jti) {
        return false;
    }

    /** Returns immutable authentication provenance for the active internal session JTI. */
    default Optional<SessionMetadata> findSessionMetadata(String userId, String jti) {
        return Optional.empty();
    }

    /**
     * Atomically replaces the current refresh secret while retaining its family.
     *
     * <p>Only one concurrent caller may advance a family. Reuse after advancement
     * is replay: the implementation revokes the active family member and throws
     * {@link io.github.brenomega.authkit.exception.TokenFamilyCompromisedException}.
     * A missing, expired or otherwise invalid token returns {@code false}.</p>
     *
     * @param durationDays replacement lifetime in days
     * @return {@code true} only for the call that completed rotation
     */
    boolean rotateRefreshToken(String userId, String currentJti, String currentRawToken,
                               String nextJti, String nextRawToken, long durationDays,
                               long securityVersion);

    /**
     * Returns a non-snapshot page of sessions without exposing internal JTIs.
     *
     * <p>The limit is from 1 through 100. Continuation cursors are opaque,
     * short-lived, bound to their owner and consumed on use; callers must not
     * infer stable ordering or snapshot isolation.</p>
     *
     * @param cursor continuation cursor, or {@code null} for the first page
     * @throws io.github.brenomega.authkit.exception.InvalidSessionCursorException
     *         if the cursor or limit is invalid, expired, reused or owner-mismatched
     */
    SessionPage listSessions(String userId, int limit, String cursor);

    /** Revokes a user-owned session addressed by its opaque public identifier. */
    void revokeSession(String userId, String publicSessionId);

    /** Revokes by internal JTI for trusted token-processing code. */
    void revokeSessionByJti(String userId, String jti);

    /**
     * Updates bounded activity metadata when the last stored update is older than
     * the supplied throttle interval.
     *
     * @param throttleSeconds minimum persistence interval in seconds
     */
    void touchSession(String userId, String jti, Instant seenAt, String maskedIp, long throttleSeconds);

    /** Revokes every first-party session owned by a user. */
    void revokeAllSessions(String userId);

    /** Revokes every session except the trusted current JTI. */
    void revokeOtherSessions(String userId, String currentJti);

    /** Idempotently removes sessions issued before a durable account security version. */
    void revokeSessionsBeforeVersion(String userId, long minimumVersion, String preservedJti);

    /**
     * Stores the current recovery secret for a normalized email, replacing any
     * earlier unconsumed secret.
     *
     * @param durationMinutes lifetime in minutes
     */
    void storeRecoveryToken(String email, String rawToken, long durationMinutes);

    /** Applies a durable activation once; retry must neither extend expiry nor resurrect a consumed token. */
    void activateRecoveryToken(String activationId, String emailDigest, String tokenDigest, Instant expiresAt);

    /** Tests a recovery secret without consuming it. */
    boolean validateRecoveryToken(String email, String rawToken);

    /**
     * Validates and consumes a recovery secret exactly once.
     *
     * <p>Comparison, expiry enforcement and deletion must be atomic.</p>
     */
    boolean consumeRecoveryToken(String email, String rawToken);

    /**
     * Atomically reserves a valid recovery secret for a database transaction.
     *
     * <p>A claim prevents another caller from succeeding while allowing the
     * owner to complete consumption after commit or release it after rollback.</p>
     *
     * @param claimTtlSeconds claim lifetime in seconds
     */
    boolean claimRecoveryToken(String email, String rawToken, String claimId, long claimTtlSeconds);

    /** Permanently consumes a recovery secret held by the matching claim. */
    void completeRecoveryTokenClaim(String email, String claimId);

    /** Releases a matching recovery claim without consuming the underlying secret. */
    void releaseRecoveryTokenClaim(String email, String claimId);

    /** Invalidates the current recovery secret for a normalized email. */
    void revokeRecoveryToken(String email);

    /** Invalidates recovery state by its already HMAC-protected normalized-email lookup. */
    void revokeRecoveryTokenByDigest(String emailDigest);

    /** Invalidates the current recovery secret only if the supplied value matches. */
    default void revokeRecoveryTokenIfMatches(String email, String rawToken) {
        consumeRecoveryToken(email, rawToken);
    }

    /**
     * Stores a short-lived MFA login challenge without creating a session.
     *
     * @param durationMinutes challenge lifetime in minutes
     * @throws UnsupportedOperationException if challenge storage is unsupported
     */
    default void storeMfaChallenge(String userId, String jti, String rawToken, long durationMinutes) {
        throw new UnsupportedOperationException("MFA challenge storage is not configured");
    }

    /**
     * Validates and consumes an MFA login challenge exactly once.
     *
     * <p>Comparison, expiration enforcement and deletion must be atomic.</p>
     *
     * @return {@code true} only for the caller that consumed a matching challenge
     * @throws UnsupportedOperationException if challenge storage is unsupported
     */
    default boolean consumeMfaChallenge(String userId, String jti, String rawToken) {
        throw new UnsupportedOperationException("MFA challenge storage is not configured");
    }
}
