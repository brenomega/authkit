package io.github.brenomega.authkit.controller;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class ProfileIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenStorage tokenStorage;

    @SuppressWarnings("null")
    @Test
    @DisplayName("GET /me: Returns authenticated profile (RF 2.1.6)")
    void profileGet_Success() throws Exception {
        User user = new User("getme@example.com", "Pass", "John", null, true, true, null);
        user.setEmailConfirmed(true);
        userRepository.save(user);

        mockMvc.perform(get("/api/v1/users/me")
                        .with(userJwt(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.email").value("getme@example.com"))
                .andExpect(jsonPath("$.data.name").value("John"));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("PATCH /me: Updates profile successfully (RF 2.1.6)")
    void profileUpdate_Success() throws Exception {
        User user = new User("patchme@example.com", "Pass", "Old", null, true, true, null);
        user.setEmailConfirmed(true);
        userRepository.save(user);

        String payload = """
                {
                   "name": "New Name"
                }
                """;

        mockMvc.perform(patch("/api/v1/users/me")
                        .with(userJwt(user))
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("New Name"));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("PATCH /me: Blocks profile updates until email is confirmed")
    void profileUpdate_UnconfirmedEmail_Forbidden() throws Exception {
        User user = new User("unconfirmed-patch@example.com", "Pass", "Old", null, true, true, "token");
        userRepository.save(user);

        String payload = """
                {
                   "name": "Blocked Name"
                }
                """;

        mockMvc.perform(patch("/api/v1/users/me")
                        .with(userJwt(user))
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errors[0]").value("Unauthorized"));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("GET /me/consent: Returns versioned consent snapshot")
    void consentGet_Success() throws Exception {
        User user = new User("consent@example.com", "Pass", "Jane", null, true, true, null);
        user.setEmailConfirmed(true);
        user.recordConsent("terms-2026", "privacy-2026", "consent", java.time.Instant.parse("2026-01-01T00:00:00Z"));
        userRepository.save(user);

        mockMvc.perform(get("/api/v1/users/me/consent")
                        .with(userJwt(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.termsVersion").value("terms-2026"))
                .andExpect(jsonPath("$.data.privacyPolicyVersion").value("privacy-2026"))
                .andExpect(jsonPath("$.data.lawfulBasis").value("consent"));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("DELETE /me: Anonymizes direct PII and marks account deleted")
    void deleteMyAccount_AnonymizesAccount() throws Exception {
        User user = new User(
                "delete-me@example.com",
                passwordEncoder.encode("CurrentPassword123!"),
                "Delete Me",
                "555",
                true,
                true,
                null);
        user.setEmailConfirmed(true);
        userRepository.save(user);

        String payload = """
                {
                   "currentPassword": "CurrentPassword123!"
                }
                """;

        mockMvc.perform(delete("/api/v1/users/me")
                        .with(userJwt(user))
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("deleted"))
                .andExpect(jsonPath("$.data.deletedAt").exists())
                .andExpect(jsonPath("$.data.anonymizedAt").exists());

        User deletedUser = userRepository.findById(user.getId()).orElseThrow();
        org.junit.jupiter.api.Assertions.assertTrue(deletedUser.getEmail().startsWith("deleted+"));
        org.junit.jupiter.api.Assertions.assertNull(deletedUser.getName());
        org.junit.jupiter.api.Assertions.assertNull(deletedUser.getPhone());
        org.junit.jupiter.api.Assertions.assertTrue(deletedUser.isDeleted());
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("POST /me/password: Rejects oversized current password before hashing")
    void passwordChange_OversizedCurrentPassword_Returns400() throws Exception {
        User user = new User("password-dos@example.com", "Pass", "Jane", null, true, true, null);
        user.setEmailConfirmed(true);
        userRepository.save(user);

        String payload = """
                {
                   "currentPassword": "%s",
                   "newPassword": "NewPassword123!"
                }
                """.formatted("A".repeat(129));

        mockMvc.perform(post("/api/v1/users/me/password")
                        .with(userJwt(user))
                        .contentType("application/json")
                        .content(payload))
                .andExpect(status().isBadRequest());
    }

    private org.springframework.test.web.servlet.request.RequestPostProcessor userJwt(User user) {
        String jti = java.util.UUID.randomUUID().toString();
        var refreshToken = RefreshTokenCodec.issue(user.getId().toString(), jti);
        tokenStorage.storeRefreshToken(user.getId().toString(), jti, refreshToken.rawToken(), 7);
        return jwt().jwt(builder -> builder
                .subject(user.getId().toString())
                .claim("jti", jti)
                .claim("tenant_id", user.getTenantId().toString()));
    }
}
