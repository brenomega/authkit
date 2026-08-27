package io.github.brenomega.authkit.controller;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventRepository;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxRepository;
import io.github.brenomega.authkit.repository.UserRepository;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class RegistrationIntegrationTest {

    private static final String QUERY_TOKEN_MARKER = "?" + "token=";
    private static final Pattern FRAGMENT_TOKEN = Pattern.compile("#token=([A-Za-z0-9_-]+)");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EmailOutboxRepository emailOutboxRepository;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Autowired
    private ConsentEventRepository consentEventRepository;

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
                   "password": "VaultRiver73!",
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

        var user = userRepository.findByEmail("legit@example.com").orElseThrow();
        var consentHistory = consentEventRepository.findByUserIdOrderByAcceptedAtDesc(user.getId());
        assertEquals(1, consentHistory.size());
        assertNotNull(consentHistory.getFirst().getEventHash());
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Email confirmation endpoint confirms account and consumes token")
    void emailConfirmation_success() throws Exception {
        String payload = """
                {
                   "email": "confirm-flow@example.com",
                   "password": "VaultRiver73!",
                   "termsAccepted": true,
                   "privacyPolicyAccepted": true
                }
                """;

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isCreated());

        var user = userRepository.findByEmail("confirm-flow@example.com").orElseThrow();
        String storedTokenHash = user.getEmailConfirmationToken();
        assertNotNull(storedTokenHash);

        String htmlBody = emailOutboxRepository.findTopByRecipientOrderByCreatedAtDesc("confirm-flow@example.com")
                .orElseThrow()
                .getBody();
        assertTrue(htmlBody.contains("#token="));
        assertFalse(htmlBody.contains(QUERY_TOKEN_MARKER));
        Matcher tokenMatcher = FRAGMENT_TOKEN.matcher(htmlBody);
        assertTrue(tokenMatcher.find());
        String token = tokenMatcher.group(1);
        assertNotEquals(storedTokenHash, token);

        mockMvc.perform(post("/api/v1/auth/email-confirmation/confirm")
                        .param("token", token))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/v1/auth/email-confirmation/confirm")
                        .contentType("application/json")
                        .content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value("Email confirmed successfully."));

        mockMvc.perform(post("/api/v1/auth/email-confirmation/confirm")
                        .contentType("application/json")
                        .content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().isBadRequest());

        var confirmedUser = userRepository.findByEmail("confirm-flow@example.com").orElseThrow();
        assertTrue(confirmedUser.isEmailConfirmed());
        assertNull(confirmedUser.getEmailConfirmationToken());
        assertTrue(securityEventRepository.findTop100ByTargetUserIdOrderByOccurredAtDesc(confirmedUser.getId())
                .stream()
                .anyMatch(event -> event.getEventType() == SecurityEventType.EMAIL_VERIFIED));
    }
}
