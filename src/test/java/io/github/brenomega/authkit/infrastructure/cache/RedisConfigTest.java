package io.github.brenomega.authkit.infrastructure.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import io.lettuce.core.RedisClient;

class RedisConfigTest {

    @Test
    @DisplayName("Redis backend exposes the native Lettuce client for distributed controls")
    void redisBackendExposesNativeLettuceClient() {
        RedisClient nativeClient = mock(RedisClient.class);
        LettuceConnectionFactory connectionFactory = mock(LettuceConnectionFactory.class);
        when(connectionFactory.getNativeClient()).thenReturn(nativeClient);

        new ApplicationContextRunner()
                .withInitializer(context -> context.getEnvironment().setActiveProfiles("prod"))
                .withBean(LettuceConnectionFactory.class, () -> connectionFactory)
                .withUserConfiguration(RedisConfig.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(StringRedisTemplate.class);
                    assertThat(context).hasSingleBean(RedisClient.class);
                    assertThat(context.getBean(RedisClient.class)).isSameAs(nativeClient);
                });
    }

    @Test
    @DisplayName("Redis backend fails fast when the connection factory is not Lettuce-backed")
    void redisBackendRejectsNonLettuceConnectionFactory() {
        RedisConfig config = new RedisConfig();
        RedisConnectionFactory connectionFactory = mock(RedisConnectionFactory.class);

        assertThatThrownBy(() -> config.redisClient(connectionFactory))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Lettuce");
    }

    @Test
    @DisplayName("JDBC token backend does not load Redis infrastructure")
    void jdbcBackendDoesNotLoadRedisInfrastructure() {
        new ApplicationContextRunner()
                .withInitializer(context -> context.getEnvironment().setActiveProfiles("prod"))
                .withPropertyValues("authkit.auth.token-storage.backend=jdbc")
                .withUserConfiguration(RedisConfig.class)
                .run(context -> {
                    assertThat(context).doesNotHaveBean(StringRedisTemplate.class);
                    assertThat(context).doesNotHaveBean(RedisClient.class);
                });
    }
}
