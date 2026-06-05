package io.github.brenomega.authkit.infrastructure.network.rateLimit;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import org.springframework.beans.factory.annotation.Autowired;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "authkit.auth.abuse-control.fail-closed-high-risk=true"
})
class EndpointAbuseRateLimitingFilterTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("High-risk abuse fail-closed mode returns opaque 503 from filter")
    void failClosedRedisLossReturnsOpaqueServiceUnavailableEnvelope() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content("""
                                {
                                  "email": "failclosed@example.com",
                                  "password": "Password123!"
                                }
                                """))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.data").doesNotExist())
                .andExpect(jsonPath("$.errors[0]")
                        .value("Authentication service is temporarily unavailable. Please try again later."))
                .andExpect(jsonPath("$.timestamp").exists());
    }
}
