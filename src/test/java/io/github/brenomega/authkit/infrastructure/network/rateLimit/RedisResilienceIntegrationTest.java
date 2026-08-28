package io.github.brenomega.authkit.infrastructure.network.rateLimit;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

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

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .header("CF-Connecting-IP", "2.2.2.2")
                            .contentType("application/json")
                            .content(payload))
                    .andExpect(status().isUnauthorized());
        }
    }
}
