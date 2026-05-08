package io.github.brenomega.authkit.infrastructure.network.rateLimit;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.brenomega.authkit.infrastructure.network.rateLimit.RateLimitingFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration test verifying the resilience of {@link RateLimitingFilter}
 * when Redis is unavailable (DT 3.2.21, DT 3.1.18).
 *
 * <p>In the test profile, no {@code RedisClient} bean is registered, so the
 * filter initializes with {@code proxyManager = null} (Layer 1 only). This
 * test verifies that:</p>
 * <ul>
 *   <li>The filter does NOT throw 500 Internal Server Error when Redis is absent.</li>
 *   <li>Requests are processed cleanly via the Layer 1 Caffeine cache.</li>
 *   <li>Authentication endpoints remain functional in fail-open mode.</li>
 * </ul>
 *
 * <p><strong>Architecture Note:</strong> With the new bean-based design, the
 * {@code RedisClient} is injected as {@code Optional<RedisClient>}. When
 * absent, the {@code ProxyManager} is never created and Layer 2 is completely
 * skipped — no reflection, no reconnection attempts, no self-healing loops.</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class RedisResilienceIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Fail-Open: Filter operates cleanly without Redis, no 500 errors (DT 3.1.18, DT 3.2.21)")
    void rateLimiter_failsOpenWithoutRedis() throws Exception {
        String payload = """
                {
                   "email": "resilience@example.com",
                   "password": "Password123!"
                }
                """;

        // With no Redis, Layer 2 is completely disabled.
        // The filter should process the request via Layer 1 (Caffeine) only,
        // then pass through to authentication (which returns 401 — user doesn't exist).
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("CF-Connecting-IP", "1.1.1.1")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Fail-Open: Multiple rapid requests are handled without 500 when Redis is absent (DT 3.2.21)")
    void rateLimiter_handlesMultipleRequestsWithoutRedis() throws Exception {
        String payload = """
                {
                   "email": "burst@example.com",
                   "password": "Password123!"
                }
                """;

        // Fire multiple requests to verify stability under load without Redis.
        // All should return either 401 (auth failure) — never 500.
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .header("CF-Connecting-IP", "2.2.2.2")
                            .contentType("application/json")
                            .content(payload))
                    .andExpect(status().isUnauthorized());
        }
    }
}
