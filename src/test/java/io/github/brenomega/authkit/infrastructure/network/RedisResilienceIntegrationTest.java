package io.github.brenomega.authkit.infrastructure.network;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class RedisResilienceIntegrationTest {

    @TestConfiguration
    static class TestConfig {
        @Bean
        public RedisConnectionFactory redisConnectionFactory() {
            return new LettuceConnectionFactory();
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @MockitoSpyBean
    private RedisConnectionFactory redisConnectionFactory;

    @Test
    @DisplayName("Self-Healing: RateLimitingFilter fails-open when Redis is down, then recovers when Redis is up (DT 3.2.21)")
    void rateLimiter_selfHealsAfterRedisFailure() throws Exception {
        String payload = """
                {
                   "email": "resilience@example.com",
                   "password": "Password123!"
                }
                """;

        // 1. Simulate initial failure: getNativeClient() throws exception
        if (redisConnectionFactory instanceof LettuceConnectionFactory lettuceFactory) {
            doThrow(new RuntimeException("Redis is Down!"))
                    .when(lettuceFactory).getNativeClient();
        }

        // 2. Perform request: should fail-open (rely on Caffeine) and return 401 (since user doesn't exist)
        // instead of 500.
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("CF-Connecting-IP", "1.1.1.1")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isUnauthorized());

        // 3. Simulate Recovery: next call to getNativeClient() returns the real client
        if (redisConnectionFactory instanceof LettuceConnectionFactory lettuceFactory) {
            doCallRealMethod().when(lettuceFactory).getNativeClient();
        }

        // 4. Perform request again: RateLimitingFilter should attempt re-initialization
        // and successfully use the ProxyManager (if Redis is actually available in the environment).
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("CF-Connecting-IP", "1.1.1.1")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isUnauthorized());
                
        // Verification: check that getNativeClient was called again (attempted re-init)
        if (redisConnectionFactory instanceof LettuceConnectionFactory lettuceFactory) {
            verify(lettuceFactory, atLeast(2)).getNativeClient();
        }
    }
}
