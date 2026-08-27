package io.github.brenomega.authkit.infrastructure.cache;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;
import java.util.HashSet;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.infrastructure.audit.AuditDigestService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.exception.InvalidSessionCursorException;

@Testcontainers(disabledWithoutDocker = true)
class RedisTokenStorageContainerTest {

    @SuppressWarnings("resource")
    @Container
    private static final GenericContainer<?> REDIS =
            new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                    .withExposedPorts(6379);

    @Test
    @DisplayName("Refresh token rotation and revocation scripts run against real Redis")
    void refreshTokenScripts_runAgainstRedis() {
        @SuppressWarnings("null")
        RedisStandaloneConfiguration configuration =
                new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
        LettuceConnectionFactory connectionFactory = new LettuceConnectionFactory(configuration);
        connectionFactory.afterPropertiesSet();

        try {
            StringRedisTemplate template = new StringRedisTemplate(connectionFactory);
            template.afterPropertiesSet();
            RedisTokenStorage storage = storage(template);

            String userId = UUID.randomUUID().toString();
            String currentJti = UUID.randomUUID().toString();
            String nextJti = UUID.randomUUID().toString();
            var currentToken = RefreshTokenCodec.issue(userId, currentJti);
            var nextToken = RefreshTokenCodec.issueRotated(userId, nextJti, currentToken.familyId());

            storage.storeRefreshToken(userId, currentJti, currentToken.rawToken(), 7);
            assertTrue(storage.rotateRefreshToken(
                    userId,
                    currentJti,
                    currentToken.rawToken(),
                    nextJti,
                    nextToken.rawToken(),
                    7));

            assertFalse(storage.validateToken(userId, currentJti, currentToken.rawToken()));
            assertTrue(storage.validateToken(userId, nextJti, nextToken.rawToken()));

            storage.revokeOtherSessions(userId, nextJti);
            assertTrue(storage.validateToken(userId, nextJti, nextToken.rawToken()));

            String mfaJti = UUID.randomUUID().toString();
            String mfaChallenge = "mfa-token-" + UUID.randomUUID();
            storage.storeMfaChallenge(userId, mfaJti, mfaChallenge, 5);
            assertTrue(storage.consumeMfaChallenge(userId, mfaJti, mfaChallenge));
            assertFalse(storage.consumeMfaChallenge(userId, mfaJti, mfaChallenge));
        } finally {
            connectionFactory.destroy();
        }
    }

    @Test
    @DisplayName("Recovery claim compensation and completion run atomically against real Redis")
    void recoveryClaimLifecycleRunsAgainstRedis() {
        @SuppressWarnings("null")
        RedisStandaloneConfiguration configuration =
                new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
        LettuceConnectionFactory connectionFactory = new LettuceConnectionFactory(configuration);
        connectionFactory.afterPropertiesSet();

        try {
            StringRedisTemplate template = new StringRedisTemplate(connectionFactory);
            template.afterPropertiesSet();
            RedisTokenStorage storage = storage(template);
            String email = "redis-claim-" + UUID.randomUUID() + "@example.test";
            String token = "recovery-" + UUID.randomUUID();

            storage.storeRecoveryToken(email, token, 15);
            assertTrue(storage.claimRecoveryToken(email, token, "claim-1", 300));
            assertFalse(storage.claimRecoveryToken(email, token, "claim-2", 300));
            storage.releaseRecoveryTokenClaim(email, "claim-1");
            assertTrue(storage.claimRecoveryToken(email, token, "claim-2", 300));
            storage.completeRecoveryTokenClaim(email, "claim-2");
            assertFalse(storage.validateRecoveryToken(email, token));
        } finally {
            connectionFactory.destroy();
        }
    }

    @Test
    @DisplayName("Session pagination is bounded, complete, user-bound, and rejects expired cursors")
    void sessionPaginationUsesOpaqueBoundedCursors() {
        @SuppressWarnings("null")
        RedisStandaloneConfiguration configuration =
                new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
        LettuceConnectionFactory connectionFactory = new LettuceConnectionFactory(configuration);
        connectionFactory.afterPropertiesSet();
        try {
            StringRedisTemplate template = new StringRedisTemplate(connectionFactory);
            template.afterPropertiesSet();
            RedisTokenStorage storage = storage(template);
            String userId = UUID.randomUUID().toString();
            for (int index = 0; index < 250; index++) {
                String jti = UUID.randomUUID().toString();
                var token = RefreshTokenCodec.issue(userId, jti);
                storage.storeRefreshToken(userId, jti, token.rawToken(), 7);
            }

            HashSet<String> seen = new HashSet<>();
            String cursor = null;
            do {
                var page = storage.listSessions(userId, 37, cursor);
                assertTrue(page.items().size() <= 37);
                page.items().forEach(item -> assertTrue(seen.add(item.jti()), "duplicate session " + item.jti()));
                cursor = page.nextCursor();
            } while (cursor != null);
            assertEquals(250, seen.size());

            var firstPage = storage.listSessions(userId, 1, null);
            assertThrows(InvalidSessionCursorException.class,
                    () -> storage.listSessions(UUID.randomUUID().toString(), 1, firstPage.nextCursor()));

            var expiringPage = storage.listSessions(userId, 1, null);
            template.delete("session:cursor:" + expiringPage.nextCursor());
            assertThrows(InvalidSessionCursorException.class,
                    () -> storage.listSessions(userId, 1, expiringPage.nextCursor()));
        } finally {
            connectionFactory.destroy();
        }
    }

    @Test
    @DisplayName("Session metadata rotation, throttled touch, and public-ID revocation are atomic in Redis")
    void sessionMetadataLifecycleRunsAgainstRedis() {
        RedisStandaloneConfiguration configuration =
                new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379));
        LettuceConnectionFactory connectionFactory = new LettuceConnectionFactory(configuration);
        connectionFactory.afterPropertiesSet();
        try {
            StringRedisTemplate template = new StringRedisTemplate(connectionFactory);
            template.afterPropertiesSet();
            RedisTokenStorage storage = storage(template);
            String userId = UUID.randomUUID().toString();
            String jti = UUID.randomUUID().toString();
            var current = RefreshTokenCodec.issue(userId, jti);
            Instant created = Instant.now().minusSeconds(600);
            var metadata = new io.github.brenomega.authkit.service.spi.SessionMetadata(
                    UUID.randomUUID().toString(), jti, created, created, Instant.now().plusSeconds(604800),
                    List.of("pwd", "totp"), "Firefox on Linux", "Work laptop",
                    "192.0.2.***", "192.0.2.***");
            storage.storeRefreshToken(userId, jti, current.rawToken(), 7, metadata);

            storage.touchSession(userId, jti, created.plusSeconds(100), "198.51.100.***", 300);
            assertEquals(created.getEpochSecond(),
                    storage.listSessions(userId, 10, null).items().get(0).lastSeenAt().getEpochSecond());
            storage.touchSession(userId, jti, Instant.now(), "198.51.100.***", 300);

            String nextJti = UUID.randomUUID().toString();
            var next = RefreshTokenCodec.issueRotated(userId, nextJti, current.familyId());
            assertTrue(storage.rotateRefreshToken(userId, jti, current.rawToken(), nextJti, next.rawToken(), 7));
            var rotated = storage.listSessions(userId, 10, null).items().get(0);
            assertEquals(metadata.publicSessionId(), rotated.publicSessionId());
            assertEquals("Work laptop", rotated.deviceLabel());
            assertEquals(List.of("pwd", "totp"), rotated.initialAmr());
            storage.revokeSession(userId, rotated.publicSessionId());
            assertFalse(storage.isSessionActive(userId, nextJti));
        } finally {
            connectionFactory.destroy();
        }
    }

    private RedisTokenStorage storage(StringRedisTemplate template) {
        AuthProperties properties = new AuthProperties();
        properties.getAudit().setHashPepper("container-test-audit-hash-pepper-32-bytes");
        return new RedisTokenStorage(template, new AuditDigestService(properties));
    }
}
