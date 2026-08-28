package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class LockoutManagementIntegrationTest {

    private static final Pattern FRAGMENT_TOKEN = Pattern.compile("#token=([A-Za-z0-9_-]+)");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegistrationService registrationService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EmailOutboxRepository emailOutboxRepository;

    @Autowired
    private TokenStorage tokenStorage;

    @SuppressWarnings("null")
@Test
    @DisplayName("Lockout Lifecycle: 5 failures -> management blocked -> reset -> unlocked (DT 3.2.23)")
    void lockoutLifecycle_ManagementBlocked_ThenReset() throws Exception {
        String email = "lockout-test@example.com";
        String password = "ValidPass123!";
        String newPassword = "ResetPass999!";

        var user = registrationService.registerUser(new RegisterRequest(email, password, true, true));
        user.setEmailConfirmed(true);
        userRepository.save(user);
        user.getId().toString();

        emailOutboxRepository.deleteAll();

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .contentType("application/json")
                            .content("{\"email\": \"" + email + "\", \"password\": \"WRONG\"}"))
                    .andExpect(status().isUnauthorized());
        }

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content("{\"email\": \"" + email + "\", \"password\": \"WRONG\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errors[0]").value("Invalid email or password"));

        mockMvc.perform(post("/api/v1/users/me/password")
                        .with(userJwt(user))
                        .contentType("application/json")
                        .content(
                                "{\"currentPassword\": \"" + password
                                        + "\", \"newPassword\": \"" + newPassword + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.errors[0]").value(
                        "Account is locked due to too many failed attempts. Reset your password to unlock."));

        mockMvc.perform(delete("/api/v1/users/me/sessions/some-jti")
                        .with(userJwt(user)))
                .andExpect(status().isForbidden());

        mockMvc.perform(post("/api/v1/auth/password-recovery/request")
                        .contentType("application/json")
                        .content("{\"email\": \"" + email + "\"}"))
                .andExpect(status().isOk());

        String htmlBody = emailOutboxRepository.findTopByRecipientOrderByCreatedAtDesc(email)
                .orElseThrow()
                .getBody();
        Matcher tokenMatcher = FRAGMENT_TOKEN.matcher(htmlBody);
        assertTrue(tokenMatcher.find());
        String token = tokenMatcher.group(1);

        mockMvc.perform(post("/api/v1/auth/password-recovery/reset")
                        .param("email", email)
                        .contentType("application/json")
                        .content("{\"token\": \"" + token + "\", \"newPassword\": \"" + newPassword + "\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content("{\"email\": \"" + email + "\", \"password\": \"" + newPassword + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").exists());
    }

    private org.springframework.test.web.servlet.request.RequestPostProcessor userJwt(User user) {
        String jti = UUID.randomUUID().toString();
        var refreshToken = RefreshTokenCodec.issue(user.getId().toString(), jti);
        tokenStorage.storeRefreshToken(user.getId().toString(), jti, refreshToken.rawToken(), 7);
        return jwt().jwt(builder -> builder
                .claims(claims -> claims.remove("scope"))
                .subject(user.getId().toString())
                .audience(List.of("authkit-api"))
                .claim("token_use", "first_party_access")
                .claim("jti", jti)
                .claim("tenant_id", user.getTenantId().toString()));
    }
}
