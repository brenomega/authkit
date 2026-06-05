package io.github.brenomega.authkit.infrastructure.cache;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;
import java.util.HashSet;

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
            RedisTokenStorage storage = new RedisTokenStorage(template);

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
            RedisTokenStorage storage = new RedisTokenStorage(template);
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
                page.items().forEach(item -> assertTrue(seen.add(item), "duplicate session " + item));
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
}
