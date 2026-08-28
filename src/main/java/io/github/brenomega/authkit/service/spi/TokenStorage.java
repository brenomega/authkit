package io.github.brenomega.authkit.service.spi;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface TokenStorage {

    default void storeRefreshToken(String userId, String jti, String rawToken, long durationDays) {
        Instant now = Instant.now();
        storeRefreshToken(userId, jti, rawToken, durationDays, new SessionMetadata(
                UUID.randomUUID().toString(), jti, now, now,
                now.plusSeconds(Math.multiplyExact(durationDays, 86_400L)),
                List.of(), "Unknown client", null, "unknown", "unknown"));
    }

    void storeRefreshToken(String userId, String jti, String rawToken, long durationDays,
                           SessionMetadata metadata);

    boolean validateToken(String userId, String jti, String rawToken);

    default boolean isSessionActive(String userId, String jti) {
        return false;
    }

    boolean rotateRefreshToken(String userId, String currentJti, String currentRawToken,
                               String nextJti, String nextRawToken, long durationDays);

    SessionPage listSessions(String userId, int limit, String cursor);

    void revokeSession(String userId, String publicSessionId);

    void revokeSessionByJti(String userId, String jti);

    void touchSession(String userId, String jti, Instant seenAt, String maskedIp, long throttleSeconds);

    void revokeAllSessions(String userId);

    void revokeOtherSessions(String userId, String currentJti);

    void storeRecoveryToken(String email, String rawToken, long durationMinutes);

    boolean validateRecoveryToken(String email, String rawToken);

    boolean consumeRecoveryToken(String email, String rawToken);

    boolean claimRecoveryToken(String email, String rawToken, String claimId, long claimTtlSeconds);

    void completeRecoveryTokenClaim(String email, String claimId);

    void releaseRecoveryTokenClaim(String email, String claimId);

    void revokeRecoveryToken(String email);

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
