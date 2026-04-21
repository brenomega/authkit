package io.github.brenomega.authkit.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class RegistrationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private QueuePublisher<EmailPayload> emailPublisher;

    @Test
    @DisplayName("Registers user and prevents mass assignment maliciously attempting to inject role")
    void registration_preventsMassAssignment() throws Exception {
        // Attempting to explicitly force role = ADMIN
        String payload = """
                {
                   "email": "hacker@example.com",
                   "password": "SuperSecret123!",
                   "name": "Ignored Hacker",
                   "termsAccepted": true,
                   "privacyPolicyAccepted": true,
                   "role": "ADMIN"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType("application/json")
                        .content(payload))
                // The global ObjectMapper is configured with strict-duplicate-detection AND 
                // fail-on-unknown-properties. Because `role` is not in RegisterRequest DTO,
                // Spring returns 400 Bad Request directly, protecting the entity.
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors").isArray());
    }

    @Test
    @DisplayName("Successful registration creates user and returns expected structure")
    void registration_success() throws Exception {
        String payload = """
                {
                   "email": "legit@example.com",
                   "password": "LegitPassword!",
                   "termsAccepted": true,
                   "privacyPolicyAccepted": true
                }
                """;

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.email").value("legit@example.com"))
                .andExpect(jsonPath("$.data.tenantId").exists())
                .andExpect(jsonPath("$.data.id").exists())
                // Ensure no password hashes or tokens are leaked in the response
                .andExpect(jsonPath("$.data.password").doesNotExist())
                .andExpect(jsonPath("$.data.emailConfirmationToken").doesNotExist());
    }
}
