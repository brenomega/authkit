package io.github.brenomega.authkit.infrastructure.network.rateLimit;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.repository.UserRepository;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@org.springframework.test.context.TestPropertySource(properties = {
    "network.security.rate-limit.local-capacity=10"
})
public class NetworkSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("Origin Firewall: untrusted IP returns 403 (DT 3.2.19)")
    void originFirewall_untrustedIp_returns403() throws Exception {

        mockMvc.perform(post("/api/v1/auth/register")
                        .with(request -> {
                            request.setRemoteAddr("8.8.8.8");
                            return request;
                        })
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("RateLimitingFilter prevents bursts and blocks at threshold (DT 3.2.21)")
    void rateLimiter_blocksExcessRequests() throws Exception {
        String payload = """
                {
                   "email": "rate@example.com",
                   "password": "Password123!"
                }
                """;

        String uniqueIp = "100.100.100.100";
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .header("CF-Connecting-IP", uniqueIp)
                            .contentType("application/json")
                            .content(payload))

                   .andReturn();
        }

        mockMvc.perform(post("/api/v1/auth/login")
                        .header("CF-Connecting-IP", uniqueIp)
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"))
                .andExpect(jsonPath("$.code").value("rate_limit_exceeded"))
                .andExpect(jsonPath("$.requestId").isNotEmpty());
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Progressive Lockout keeps brute-force responses generic (DT 3.2.15)")
    void progressiveLockout_stealthResponse() throws Exception {
        String email = "brute@example.com";
        String payload = """
                {
                   "email": "%s",
                   "password": "WrongPassword!"
                }
                """.formatted(email);

        userRepository.save(new User(email, "Hash123", null, true, true, null));

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .header("CF-Connecting-IP", "127.0.0.12")
                            .contentType("application/json")
                            .content(payload))
                    .andExpect(status().isUnauthorized());
        }

        mockMvc.perform(post("/api/v1/auth/login")
                        .header("CF-Connecting-IP", "127.0.0.12")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errors[0]").value("Invalid email or password"));
    }

    @Test
    @DisplayName("Stateless Simulation: Mocking horizontal nodes verifies Shared Bucket Logic degradation accurately")
    void rateLimiter_distributedMockTest() throws Exception {

        String payload = """
                {
                   "email": "distributed@example.com",
                   "password": "Password123!"
                }
                """;
        String uniqueIp = "200.200.200.200";
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .header("CF-Connecting-IP", uniqueIp)
                            .contentType("application/json")
                            .content(payload));
        }

        mockMvc.perform(post("/api/v1/auth/login")
                        .header("CF-Connecting-IP", uniqueIp)
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    @DisplayName("Failover Check: Redis exhaustion fails-open gracefully leveraging local Caffeine layer (DT 3.2.21)")
    void rateLimiter_failOpenTest() throws Exception {

        String payload = """
                {
                   "email": "failopen@example.com",
                   "password": "Password123!"
                }
                """;
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("CF-Connecting-IP", "99.99.99.99")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isUnauthorized());
    }
}
