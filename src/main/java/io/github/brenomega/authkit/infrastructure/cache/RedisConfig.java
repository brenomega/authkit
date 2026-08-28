package io.github.brenomega.authkit.infrastructure.cache;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.lang.NonNull;

import io.lettuce.core.RedisClient;

@Configuration
@Profile("!test")
@ConditionalOnProperty(prefix = "authkit.auth.token-storage", name = "backend",
        havingValue = "redis", matchIfMissing = true)
public class RedisConfig {

    @Bean
    public StringRedisTemplate stringRedisTemplate(@NonNull RedisConnectionFactory connectionFactory) {
        return new StringRedisTemplate(connectionFactory);
    }

    @Bean
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
