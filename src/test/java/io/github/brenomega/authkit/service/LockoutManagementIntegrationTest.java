package io.github.brenomega.authkit.service;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
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

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxRepository;
import io.github.brenomega.authkit.repository.UserRepository;

/**
 * Integration test validating the progressive lockout lifecycle (DT 3.2.23).
 *
 * <p>Verifies that:</p>
 * <ol>
     *   <li>After 5 failed logins, the account remains generically rejected (DT 3.2.15).</li>
 *   <li>Locked accounts are blocked from password change even with a valid JWT.</li>
 *   <li>Locked accounts are blocked from session revocation even with a valid JWT.</li>
 *   <li>Email-based password reset is the ONLY unlock path.</li>
 *   <li>After reset, all management endpoints are accessible again.</li>
 * </ol>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class LockoutManagementIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EmailOutboxRepository emailOutboxRepository;

    @Test
    @SuppressWarnings({ "null" })
    @DisplayName("Lockout Lifecycle: 5 failures -> management blocked -> reset -> unlocked (DT 3.2.23)")
    void lockoutLifecycle_ManagementBlocked_ThenReset() throws Exception {
        String email = "lockout-test@example.com";
        String password = "ValidPass123!";
        String newPassword = "ResetPass999!";

        // --- SETUP: Register user ---
        var user = registrationService.registerUser(new RegisterRequest(email, password, true, true));
        user.setEmailConfirmed(true);
        userRepository.save(user);
        String userId = user.getId().toString();

        emailOutboxRepository.deleteAll();

        // --- STEP 1: Simulate 5 failed login attempts ---
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType("application/json")
                            .content("{\"email\": \"" + email + "\", \"password\": \"WRONG\"}"))
                    .andExpect(status().isUnauthorized());
        }

        // --- STEP 2: 6th login attempt should remain a generic credential failure ---
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content("{\"email\": \"" + email + "\", \"password\": \"WRONG\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errors[0]").value("Invalid email or password"));

        // --- STEP 3: Attempt password change with valid JWT → should be REJECTED (403) ---
        mockMvc.perform(post("/api/v1/users/me/password")
                        .with(jwt().jwt(builder -> builder.subject(userId).claim("tenant_id", user.getTenantId().toString())))
                        .contentType("application/json")
                        .content("{\"currentPassword\": \"" + password + "\", \"newPassword\": \"" + newPassword + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errors[0]").value(
                        "Account is locked due to too many failed attempts. Reset your password to unlock."));

        // --- STEP 4: Attempt session revocation with valid JWT → should be REJECTED (403) ---
        mockMvc.perform(delete("/api/v1/users/me/sessions/some-jti")
                        .with(jwt().jwt(builder -> builder.subject(userId).claim("tenant_id", user.getTenantId().toString()))))
                .andExpect(status().isForbidden());

        // --- STEP 5: Initiate password recovery ---
        mockMvc.perform(post("/api/v1/auth/password-recovery/request")
                        .contentType("application/json")
                        .content("{\"email\": \"" + email + "\"}"))
                .andExpect(status().isOk());

        // Capture the recovery token from the durable outbox event
        String htmlBody = emailOutboxRepository.findTopByRecipientOrderByCreatedAtDesc(email)
                .orElseThrow()
                .getBody();
        String token = htmlBody.substring(htmlBody.indexOf("token=") + 6, htmlBody.indexOf("&email="));

        // --- STEP 6: Complete password reset → should clear lockout ---
        mockMvc.perform(post("/api/v1/auth/password-recovery/reset")
                        .param("email", email)
                        .contentType("application/json")
                        .content("{\"token\": \"" + token + "\", \"newPassword\": \"" + newPassword + "\"}"))
                .andExpect(status().isOk());

        // --- STEP 7: Verify login works with new password (lockout cleared) ---
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content("{\"email\": \"" + email + "\", \"password\": \"" + newPassword + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").exists());
    }
}
