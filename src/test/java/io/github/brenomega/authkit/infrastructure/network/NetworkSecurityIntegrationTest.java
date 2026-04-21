package io.github.brenomega.authkit.infrastructure.network;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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
public class NetworkSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("Cloudflare Firewall Filter blocks non-trusted origins")
    void cloudflareFilter_untrustedIp_returns403() throws Exception {
        // Simulating a direct connection bypassing Cloudflare (with an IP not in CloudflareFirewallFilter ranges)
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
        
        // Loop consuming bucket tokens using a unique spoofed IP for this exact test mapping
        String uniqueIp = "100.100.100.100";
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .header("CF-Connecting-IP", uniqueIp)
                            .contentType("application/json")
                            .content(payload))
                   // Rate Limit is capacity 10. Stealth Lockout triggers at 5. 
                   // Both will hit sequentially. We just want to exhaust the 10 tokens.
                   .andReturn();
        }

        // The 11th request matches the Bucket4j 10-limit Block
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("CF-Connecting-IP", uniqueIp)
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    @DisplayName("Progressive Lockout executes Stealth Response on brute force attempts (DT 3.2.15)")
    void progressiveLockout_stealthResponse() throws Exception {
        String email = "brute@example.com";
        String payload = """
                {
                   "email": "%s",
                   "password": "WrongPassword!"
                }
                """.formatted(email);

        userRepository.save(new User(email, "Hash123", null, null, true, true, null));

        // 5 failed attempts usually return 401 Unauthorized
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .header("CF-Connecting-IP", "127.0.0.12") // unique IP for brute force test isolation
                            .contentType("application/json")
                            .content(payload))
                    .andExpect(status().isUnauthorized());
        }

        // The 6th attempt and beyond returns 200 OK stealth-locked protecting against Enumeration
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("CF-Connecting-IP", "127.0.0.12")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value("stealth-locked"));
    }
}
