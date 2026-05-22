package io.github.brenomega.authkit.infrastructure.cache;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;

@SpringBootTest
@ActiveProfiles("test")
public class RedisTokenStorageTest {

    @Autowired
    private RedisTokenStorage redisTokenStorage;

    @Test
    @DisplayName("Hash values safely and match using constant time (DT 3.2.4 & DT 3.2.13)")
    void testStoreAndValidate_ConstantTime() {
        String userId = UUID.randomUUID().toString();
        String jti = UUID.randomUUID().toString();
        String rawToken = UUID.randomUUID().toString();

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
    @DisplayName("Recovery token consume validates and revokes atomically")
    void testConsumeRecoveryToken() {
        String email = "reset@example.com";
        String rawToken = UUID.randomUUID().toString();

        redisTokenStorage.storeRecoveryToken(email, rawToken, 15);

        assertTrue(redisTokenStorage.consumeRecoveryToken(email, rawToken));
        assertFalse(redisTokenStorage.consumeRecoveryToken(email, rawToken));
        assertFalse(redisTokenStorage.validateRecoveryToken(email, rawToken));
    }
}
