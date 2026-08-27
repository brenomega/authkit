package io.github.brenomega.authkit.infrastructure.cache;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;

import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.infrastructure.audit.AuditDigestService;

@SpringBootTest
@ActiveProfiles("test")
public class RedisTokenStorageTest {

    @Autowired
    private RedisTokenStorage redisTokenStorage;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private AuditDigestService auditDigestService;

    @Test
    @DisplayName("Hash values safely and match using constant time (DT 3.2.4 & DT 3.2.13)")
    void testStoreAndValidate_ConstantTime() {
        String userId = UUID.randomUUID().toString();
        String jti = UUID.randomUUID().toString();
        String rawToken = RefreshTokenCodec.issue(userId, jti).rawToken();

        redisTokenStorage.storeRefreshToken(userId, jti, rawToken, 7);

        // Validation against exact hash match
        assertTrue(redisTokenStorage.validateToken(userId, jti, rawToken));
        
        // Rejection of invalid payloads
        assertFalse(redisTokenStorage.validateToken(userId, jti, "forged-token"));
        
        // Ensure revocation clears it
        redisTokenStorage.revokeAllSessions(userId);
        assertFalse(redisTokenStorage.validateToken(userId, jti, rawToken));
    }

    @Test
    @DisplayName("Refresh token rotation consumes old session and stores replacement atomically")
    void testRotateRefreshToken() {
        String userId = UUID.randomUUID().toString();
        String currentJti = UUID.randomUUID().toString();
        String nextJti = UUID.randomUUID().toString();
        RefreshTokenCodec.IssuedRefreshToken currentRefreshToken = RefreshTokenCodec.issue(userId, currentJti);
        RefreshTokenCodec.IssuedRefreshToken nextRefreshToken =
                RefreshTokenCodec.issueRotated(userId, nextJti, currentRefreshToken.familyId());
        String currentToken = currentRefreshToken.rawToken();
        String nextToken = nextRefreshToken.rawToken();

        redisTokenStorage.storeRefreshToken(userId, currentJti, currentToken, 7);

        assertTrue(redisTokenStorage.rotateRefreshToken(
                userId,
                currentJti,
                currentToken,
                nextJti,
                nextToken,
                7
        ));
        assertFalse(redisTokenStorage.validateToken(userId, currentJti, currentToken));
        assertTrue(redisTokenStorage.validateToken(userId, nextJti, nextToken));
        String replayReplacementJti = UUID.randomUUID().toString();
        String replayReplacementToken =
                RefreshTokenCodec.issueRotated(userId, replayReplacementJti, currentRefreshToken.familyId()).rawToken();
        assertThrows(io.github.brenomega.authkit.exception.TokenFamilyCompromisedException.class, () ->
            redisTokenStorage.rotateRefreshToken(
                userId,
                currentJti,
                currentToken,
                replayReplacementJti,
                replayReplacementToken,
                7
            )
        );
    }

    @Test
    @DisplayName("Recovery token consume validates and revokes atomically")
    void testConsumeRecoveryToken() {
        String email = "Reset@Example.com";
        String normalizedEmail = "reset@example.com";
        String rawToken = UUID.randomUUID().toString();

        redisTokenStorage.storeRecoveryToken(email, rawToken, 15);

        assertFalse(Boolean.TRUE.equals(redisTemplate.hasKey("recovery:token:" + normalizedEmail)));
        assertFalse(Boolean.TRUE.equals(redisTemplate.hasKey("recovery:token:" + TokenHasher.sha256Hex(normalizedEmail))));
        assertTrue(Boolean.TRUE.equals(redisTemplate.hasKey("recovery:token:" + auditDigestService.hmacHex(normalizedEmail))));

        assertTrue(redisTokenStorage.consumeRecoveryToken(normalizedEmail, rawToken));
        assertFalse(redisTokenStorage.consumeRecoveryToken(normalizedEmail, rawToken));
        assertFalse(redisTokenStorage.validateRecoveryToken(normalizedEmail, rawToken));
    }

    @Test
    @DisplayName("Recovery claim is exclusive, releasable, and only completion consumes the token")
    void testRecoveryTokenClaimLifecycle() {
        String email = "claim@example.com";
        String rawToken = "recovery-" + UUID.randomUUID();
        redisTokenStorage.storeRecoveryToken(email, rawToken, 15);

        assertTrue(redisTokenStorage.claimRecoveryToken(email, rawToken, "claim-1", 300));
        assertFalse(redisTokenStorage.claimRecoveryToken(email, rawToken, "claim-2", 300));
        redisTokenStorage.releaseRecoveryTokenClaim(email, "claim-1");
        assertTrue(redisTokenStorage.claimRecoveryToken(email, rawToken, "claim-2", 300));
        redisTokenStorage.completeRecoveryTokenClaim(email, "claim-2");
        assertFalse(redisTokenStorage.validateRecoveryToken(email, rawToken));
    }

    @Test
    @DisplayName("MFA challenge consume validates and revokes atomically")
    void testConsumeMfaChallenge() {
        String userId = UUID.randomUUID().toString();
        String jti = UUID.randomUUID().toString();
        String rawToken = "mfa-token-" + UUID.randomUUID();

        redisTokenStorage.storeMfaChallenge(userId, jti, rawToken, 5);

        assertFalse(redisTokenStorage.consumeMfaChallenge(userId, jti, "forged-token"));
        assertTrue(redisTokenStorage.consumeMfaChallenge(userId, jti, rawToken));
        assertFalse(redisTokenStorage.consumeMfaChallenge(userId, jti, rawToken));
    }

    @Test
    @DisplayName("Revoking other sessions preserves current session atomically")
    void testRevokeOtherSessions() {
        String userId = UUID.randomUUID().toString();
        String currentJti = UUID.randomUUID().toString();
        String otherJti = UUID.randomUUID().toString();
        String currentToken = RefreshTokenCodec.issue(userId, currentJti).rawToken();
        String otherToken = RefreshTokenCodec.issue(userId, otherJti).rawToken();

        redisTokenStorage.storeRefreshToken(userId, currentJti, currentToken, 7);
        redisTokenStorage.storeRefreshToken(userId, otherJti, otherToken, 7);

        redisTokenStorage.revokeOtherSessions(userId, currentJti);

        assertTrue(redisTokenStorage.validateToken(userId, currentJti, currentToken));
        assertFalse(redisTokenStorage.validateToken(userId, otherJti, otherToken));
    }
}
