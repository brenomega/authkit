package io.github.brenomega.authkit.infrastructure.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration tests for the security barrier (DT 3.4.7).
 *
 * <p>Validates HTTP security behavior using the full application context
 * with MockMvc. Tests run under the {@code test} profile (H2 database,
 * external dependencies disabled).</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------------
    // Authentication (DT 3.4.3 — 401)
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("GET to protected endpoint without token returns 401 in ApiResponse envelope")
    void requestWithoutToken_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/protected"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errors").isArray())
                .andExpect(jsonPath("$.errors[0]").value("Unauthorized"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    @DisplayName("POST to login endpoint without token is permitted (permitAll)")
    void postToLogin_isPermitted() throws Exception {
        // The endpoint exists now and validates the payload, giving 400 Bad Request,
        // proving the security layer allows the request through.
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST to register endpoint without token is permitted (permitAll)")
    void postToRegister_isPermitted() throws Exception {
        // The endpoint is mapped and will fail @Valid validation (400),
        // proving the security layer allows the request through.
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    // -------------------------------------------------------------------------
    // Response envelope consistency
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Error responses follow ApiResponse structure with errors and timestamp")
    void errorResponse_followsEnvelopeStructure() throws Exception {
        mockMvc.perform(get("/api/v1/nonexistent"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.data").doesNotExist())
                .andExpect(jsonPath("$.errors").isArray())
                .andExpect(jsonPath("$.timestamp").isString());
    }

    // -------------------------------------------------------------------------
    // Security headers (DT 3.2.14)
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Response includes X-Content-Type-Options: nosniff")
    void securityHeader_nosniff() throws Exception {
        mockMvc.perform(get("/api/v1/anything"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"));
    }

    @Test
    @DisplayName("Response includes X-Frame-Options: DENY")
    void securityHeader_frameDeny() throws Exception {
        mockMvc.perform(get("/api/v1/anything"))
                .andExpect(header().string("X-Frame-Options", "DENY"));
    }
}
