package io.github.brenomega.authkit.controller;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
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
import io.github.brenomega.authkit.domain.user.enums.AccountState;
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
    @Autowired private com.fasterxml.jackson.databind.ObjectMapper json;

    @Test
    void passwordlessEmailAndMfaManagementAcceptFreshPasskeyWithoutPlaceholderPassword() throws Exception {
        User user = new User("passkey-stepup@example.com", null, "Passkey", true, true, null);
        user.setEmailConfirmed(true);
        acceptCurrentConsent(user);
        userRepository.saveAndFlush(user);
        mockMvc.perform(post("/api/v1/users/me/email-change").with(userJwt(user))
                .contentType("application/json").content("{\"newEmail\":\"passkey-new@example.com\"}"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/v1/users/me/email-change").with(passkeyJwt(user))
                .contentType("application/json").content("{\"newEmail\":\"passkey-new@example.com\"}"))
                .andExpect(status().isOk());
        var enrollment = mockMvc.perform(post("/api/v1/users/me/mfa/totp/enroll").with(passkeyJwt(user))
                .contentType("application/json").content("{}"))
                .andExpect(status().isOk()).andReturn();
        var data = json.readTree(enrollment.getResponse().getContentAsString()).get("data");
        String code = new io.github.brenomega.authkit.domain.mfa.util.TotpGenerator()
                .currentCode(data.get("secret").asText());
        var confirmation = mockMvc.perform(post("/api/v1/users/me/mfa/totp/confirm").with(passkeyJwt(user))
                .contentType("application/json").content(json.writeValueAsString(java.util.Map.of(
                        "credentialId", data.get("credentialId").asText(), "code", code))))
                .andExpect(status().isOk()).andReturn();
        String backupCode = json.readTree(confirmation.getResponse().getContentAsString())
                .get("data").get("backupCodes").get(0).asText();
        User refreshed = userRepository.findById(user.getId()).orElseThrow();
        mockMvc.perform(delete("/api/v1/users/me/mfa/totp").with(passkeyJwt(refreshed))
                .contentType("application/json").content(json.writeValueAsString(java.util.Map.of("code", backupCode))))
                .andExpect(status().isOk());
    }

    @Test
    void passwordAccountStillRequiresCurrentPasswordWhenPasskeyClaimIsPresent() throws Exception {
        User user = new User("password-stepup@example.com", passwordEncoder.encode("CurrentPassword73!"),
                "Password", true, true, null);
        user.setEmailConfirmed(true);
        acceptCurrentConsent(user);
        userRepository.saveAndFlush(user);
        mockMvc.perform(post("/api/v1/users/me/email-change").with(passkeyJwt(user))
                .contentType("application/json").content("{\"newEmail\":\"password-new@example.com\"}"))
                .andExpect(status().isUnauthorized());
    }

    private org.springframework.test.web.servlet.request.RequestPostProcessor passkeyJwt(User user) {
        String jti = UUID.randomUUID().toString();
        var refresh = RefreshTokenCodec.issue(user.getId().toString(), jti);
        Instant now = Instant.now();
        tokenStorage.storeRefreshToken(user.getId().toString(), jti, refresh.rawToken(), 7,
                new io.github.brenomega.authkit.service.spi.SessionMetadata(UUID.randomUUID().toString(), jti,
                        now, now, now.plusSeconds(604800), user.getSecurityVersion(), List.of("webauthn"),
                        "JUnit", null, "127.0.0.***", "127.0.0.***"));
        return jwt().jwt(builder -> builder.claims(claims -> claims.remove("scope"))
                .subject(user.getId().toString()).audience(List.of("authkit-api"))
                .claim("token_use", "first_party_access").claim("jti", jti)
                .claim("tenant_id", user.getTenantId().toString()).claim("amr", List.of("webauthn"))
                .claim("session_version", user.getSecurityVersion()).issuedAt(now).expiresAt(now.plusSeconds(300)));
    }

    @SuppressWarnings("null")
@Test
    @DisplayName("GET /me: Returns authenticated profile (RF 2.1.6)")
    void profileGet_Success() throws Exception {
        User user = new User("getme@example.com", "Pass", "John", true, true, null);
        user.setEmailConfirmed(true);
        acceptCurrentConsent(user);
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
        User user = new User("patchme@example.com", "Pass", "Old", true, true, null);
        user.setEmailConfirmed(true);
        acceptCurrentConsent(user);
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
        User user = new User("unconfirmed-patch@example.com", "Pass", "Old", true, true, "token");
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
        User user = new User("consent@example.com", "Pass", "Jane", true, true, null);
        user.setEmailConfirmed(true);
        user.recordConsent("terms-2026", "privacy-2026", "consent", Instant.parse("2026-01-01T00:00:00Z"));
        userRepository.save(user);

        mockMvc.perform(get("/api/v1/users/me/consent")
                        .with(userJwt(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.acceptedTermsVersion").value("terms-2026"))
                .andExpect(jsonPath("$.data.acceptedPrivacyPolicyVersion").value("privacy-2026"))
                .andExpect(jsonPath("$.data.lawfulBasis").value("consent"));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("An existing session becomes consent-limited and resumes only after exact acceptance")
    void existingSessionIsLimitedWhenPolicyVersionsAdvance() throws Exception {
        User user = new User("stale-consent@example.com", "Pass", "Stale", true, true, null);
        user.setEmailConfirmed(true);
        user.recordConsent("terms-old", "privacy-old", "consent", Instant.now().minusSeconds(60));
        userRepository.saveAndFlush(user);
        var existingSession = userJwt(user);

        mockMvc.perform(get("/api/v1/users/me/consent").with(existingSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.consentRequired").value(true))
                .andExpect(jsonPath("$.data.requiredTermsVersion").value("terms-v1"))
                .andExpect(jsonPath("$.data.requiredPrivacyPolicyVersion").value("privacy-v1"));

        mockMvc.perform(patch("/api/v1/users/me").with(existingSession)
                        .contentType("application/json").content("{\"name\":\"must not change\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("consent_required"));

        mockMvc.perform(post("/api/v1/users/me/consent").with(existingSession)
                        .contentType("application/json")
                        .content("""
                                {"termsAccepted":true,"privacyPolicyAccepted":true,
                                 "termsVersion":"terms-old","privacyPolicyVersion":"privacy-old"}
                                """))
                .andExpect(status().isConflict());

        mockMvc.perform(post("/api/v1/users/me/consent").with(existingSession)
                        .contentType("application/json")
                        .content("""
                                {"termsAccepted":true,"privacyPolicyAccepted":true,
                                 "termsVersion":"terms-v1","privacyPolicyVersion":"privacy-v1"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.consentRequired").value(false));

        mockMvc.perform(patch("/api/v1/users/me").with(existingSession)
                        .contentType("application/json").content("{\"name\":\"Current Consent\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("Current Consent"));
    }

    @SuppressWarnings("null")
@Test
    @DisplayName("DELETE /me: Enters deletion grace and preserves PII until expiry")
    void deleteMyAccount_EntersDeletionGrace() throws Exception {
        User user = new User(
                "delete-me@example.com",
                passwordEncoder.encode("CurrentPassword123!"),
                "Delete Me",
                true,
                true,
                null);
        user.setEmailConfirmed(true);
        acceptCurrentConsent(user);
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
                .andExpect(jsonPath("$.data.status").value("deletion_pending"))
                .andExpect(jsonPath("$.data.graceExpiresAt").exists())
                .andExpect(jsonPath("$.data.deletedAt").doesNotExist())
                .andExpect(jsonPath("$.data.anonymizedAt").doesNotExist());

        @SuppressWarnings("null")
        User deletedUser = userRepository.findById(user.getId()).orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals("delete-me@example.com", deletedUser.getEmail());
        org.junit.jupiter.api.Assertions.assertEquals("Delete Me", deletedUser.getName());
        org.junit.jupiter.api.Assertions.assertEquals(
                AccountState.DELETION_PENDING,
                deletedUser.getAccountState());
    }

    @SuppressWarnings("null")
@Test
    @DisplayName("POST /me/password: Rejects oversized current password before hashing")
    void passwordChange_OversizedCurrentPassword_Returns400() throws Exception {
        User user = new User("password-dos@example.com", "Pass", "Jane", true, true, null);
        user.setEmailConfirmed(true);
        acceptCurrentConsent(user);
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

@SuppressWarnings("null")
@Test
    @DisplayName("GET /me/sessions exposes safe metadata and never the internal JTI")
    void sessionsExposeSafeMetadataAndCurrentMarker() throws Exception {
        User user = new User("sessions@example.com", "Pass", "Session User", true, true, null);
        user.setEmailConfirmed(true);
        acceptCurrentConsent(user);
        userRepository.save(user);

        mockMvc.perform(get("/api/v1/users/me/sessions").with(userJwt(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.items[0].sessionId").isNotEmpty())
                .andExpect(jsonPath("$.data.items[0].jti").doesNotExist())
                .andExpect(jsonPath("$.data.items[0].current").value(true))
                .andExpect(jsonPath("$.data.items[0].createdAt").exists())
                .andExpect(jsonPath("$.data.items[0].lastSeenAt").exists())
                .andExpect(jsonPath("$.data.items[0].expiresAt").exists())
                .andExpect(jsonPath("$.data.items[0].creationIpMasked").exists())
                .andExpect(jsonPath("$.data.items[0].lastIpMasked").exists());
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
                .claim("session_version", user.getSecurityVersion())
                .claim("tenant_id", user.getTenantId().toString())
                .claim("amr", List.of("pwd")));
    }

    private void acceptCurrentConsent(User user) {
        user.recordConsent("terms-v1", "privacy-v1", "consent", Instant.now());
    }
}
