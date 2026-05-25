package io.github.brenomega.authkit.infrastructure.cache;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

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
        } finally {
            connectionFactory.destroy();
        }
    }
}
