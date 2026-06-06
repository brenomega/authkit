package io.github.brenomega.authkit.infrastructure.cache;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.lang.NonNull;

import io.lettuce.core.RedisClient;

/**
 * Infrastructure configuration for Redis caching, session management, and rate limiting.
 *
 * <p>Provides the primary {@link StringRedisTemplate} used by {@link RedisTokenStorage}
 * and {@link AccountLockoutService}, as well as the native {@link RedisClient} required
 * by the distributed rate limiting layer (DT 3.2.21).</p>
 *
 * <p>This configuration is active only in non-test profiles. The test profile
 * provides its own mock {@code StringRedisTemplate} via {@code TestCacheConfig},
 * and the {@code RateLimitingFilter} gracefully fails-open when no {@code RedisClient}
 * bean is available (DT 3.1.18).</p>
 *
 * @see RedisTokenStorage
 * @see AccountLockoutService
 */
@Configuration
@Profile("!test")
@ConditionalOnProperty(prefix = "authkit.auth.token-storage", name = "backend",
        havingValue = "redis", matchIfMissing = true)
public class RedisConfig {

    /**
     * Creates a {@link StringRedisTemplate} for key-value and hash operations.
     *
     * @param connectionFactory the auto-configured Redis connection factory
     * @return a configured template for string-based Redis operations
     */
    @Bean
    public StringRedisTemplate stringRedisTemplate(@NonNull RedisConnectionFactory connectionFactory) {
        return new StringRedisTemplate(connectionFactory);
    }

    /**
     * Exposes the native Lettuce {@link RedisClient} as a managed bean for
     * direct use by the distributed rate limiting layer (DT 3.2.21).
     *
     * <p>This eliminates the need for brittle reflection-based extraction of
     * the client from the connection factory. The {@code RateLimitingFilter}
     * injects this bean via {@code Optional<RedisClient>} to support
     * environments where Redis is not available.</p>
     *
     * @param connectionFactory the auto-configured Redis connection factory
     * @return the native Lettuce {@link RedisClient} instance
     * @throws IllegalStateException if the factory is not Lettuce-backed
     */
    @Bean
    @ConditionalOnBean(RedisConnectionFactory.class)
    public RedisClient redisClient(RedisConnectionFactory connectionFactory) {
        if (connectionFactory instanceof LettuceConnectionFactory lettuceConnectionFactory) {
            Object nativeClient = lettuceConnectionFactory.getNativeClient();
            if (nativeClient instanceof RedisClient redisClient) {
                return redisClient;
            }
        }
        throw new IllegalStateException(
                "RedisConnectionFactory is not Lettuce-backed. " +
                "Distributed rate limiting requires a LettuceConnectionFactory with a RedisClient.");
    }
}
