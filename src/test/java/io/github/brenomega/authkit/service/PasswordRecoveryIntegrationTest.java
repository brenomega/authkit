package io.github.brenomega.authkit.service;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.mockito.ArgumentCaptor;
import static org.mockito.Mockito.verify;

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.service.spi.QueuePublisher;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class PasswordRecoveryIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @MockitoBean
    private QueuePublisher<EmailPayload> emailPublisher;

    @Test
    @DisplayName("Stealth Strategy: Recovery initiation returns 200 OK regardless of email existence (DT 3.2.15)")
    void recoveryRequest_isStealth() throws Exception {
        String existingEmail = "exists@example.com";
        registrationService.registerUser(new RegisterRequest(existingEmail, "Pass123!", true, true));

        // 1. Existing email
        mockMvc.perform(post("/api/v1/auth/password-recovery/request")
                        .contentType("application/json")
                        .content("{\"email\": \"" + existingEmail + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value("If an account exists with this email, a recovery link has been sent."));

        // 2. Non-existing email
        mockMvc.perform(post("/api/v1/auth/password-recovery/request")
                        .contentType("application/json")
                        .content("{\"email\": \"nonexistent@example.com\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value("If an account exists with this email, a recovery link has been sent."));
    }

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("Password Reset: Full cycle (Recovery -> Validation -> Reset -> Revocation) (RF 2.1.4)")
    void passwordReset_fullCycle() throws Exception {
        String email = "reset@example.com";
        String oldPass = "OldPass123!";
        String newPass = "NewSecurePass999!";
        registrationService.registerUser(new RegisterRequest(email, oldPass, true, true));
        
        // Reset the mock to clear the registration email event
        org.mockito.Mockito.reset(emailPublisher);

        // 1. Request recovery
        mockMvc.perform(post("/api/v1/auth/password-recovery/request")
                        .contentType("application/json")
                        .content("{\"email\": \"" + email + "\"}"))
                .andExpect(status().isOk());

        // 2. Capture the generated token from the published email event
        ArgumentCaptor<EmailPayload> captor = ArgumentCaptor.forClass(EmailPayload.class);
        verify(emailPublisher).publish(captor.capture());
        String htmlBody = captor.getValue().htmlBody();
        String token = htmlBody.substring(htmlBody.indexOf("token=") + 6, htmlBody.indexOf("&email="));

        // 3. Reset password using the captured token
        mockMvc.perform(post("/api/v1/auth/password-recovery/reset")
                        .param("email", email)
                        .contentType("application/json")
                        .content("{\"token\": \"" + token + "\", \"newPassword\": \"" + newPass + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value("Password successfully reset."));

        // 4. Verify login works with NEW password and fails with OLD
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content("{\"email\": \"" + email + "\", \"password\": \"" + newPass + "\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content("{\"email\": \"" + email + "\", \"password\": \"" + oldPass + "\"}"))
                .andExpect(status().isUnauthorized());

        // 5. Verify token is revoked (cannot use it again)
        mockMvc.perform(post("/api/v1/auth/password-recovery/reset")
                        .param("email", email)
                        .contentType("application/json")
                        .content("{\"token\": \"" + token + "\", \"newPassword\": \"AnotherPass1!\"}"))
                .andExpect(status().isBadRequest()); // Should fail as token is gone
    }
}
