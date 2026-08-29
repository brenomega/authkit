package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import io.github.brenomega.authkit.exception.TokenRevocationUnavailableException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class OAuthTokenRevocationServiceTest {

    @Test
    void redisLookupAndWriteFailuresAreFailClosed() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        when(values.get(anyString())).thenThrow(new RedisConnectionFailureException("down"));
        doThrow(new RedisConnectionFailureException("down"))
                .when(values).set(anyString(), anyString(), any(java.time.Duration.class));

        OAuthTokenRevocationService service = redisService(redis);
        assertThrows(TokenRevocationUnavailableException.class, () -> service.isRevoked("jti-lookup"));
        assertThrows(TokenRevocationUnavailableException.class,
                () -> service.revoke("jti-write", Instant.now().plusSeconds(60)));
    }

    @Test
    void durableRedisStateSurvivesAServiceRestart() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> values = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(values);
        when(values.get("oauth:revoked-jti:jti-restart"))
                .thenReturn(Instant.now().plusSeconds(60).toString());

        OAuthTokenRevocationService restarted = redisService(redis);
        assertTrue(restarted.isRevoked("jti-restart"));
    }

    @Test
    void jdbcLookupFailureIsFailClosed() {
        JdbcOAuthTokenRevocationStore jdbc = mock(JdbcOAuthTokenRevocationStore.class);
        when(jdbc.isRevoked("jti-jdbc")).thenThrow(new IllegalStateException("database down"));
        AuthProperties properties = new AuthProperties();
        properties.getTokenStorage().setBackend("jdbc");
        OAuthTokenRevocationService service = new OAuthTokenRevocationService(
                Optional.empty(), Optional.of(jdbc), properties, new SimpleMeterRegistry());

        assertThrows(TokenRevocationUnavailableException.class, () -> service.isRevoked("jti-jdbc"));
    }

    private OAuthTokenRevocationService redisService(StringRedisTemplate redis) {
        AuthProperties properties = new AuthProperties();
        properties.getTokenStorage().setBackend("redis");
        return new OAuthTokenRevocationService(
                Optional.of(redis), Optional.empty(), properties, new SimpleMeterRegistry());
    }
}
