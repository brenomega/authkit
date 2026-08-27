package com.example.authkit.sample;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class TokenValidationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void validatorAcceptsOnlyAuthKitOAuthAccessTokensForConfiguredAudience() {
        var validator = SecurityConfig.authKitValidator(
                "http://localhost:8080",
                "sample-resource-api",
                "oauth_access");

        assertTrue(validator.validate(jwtClaims(Map.of(
                "iss", "http://localhost:8080",
                "aud", List.of("sample-resource-api"),
                "token_use", "oauth_access",
                "tenant_id", "tenant-a",
                "client_id", "sample-resource-api",
                "scope", "openid email"))).hasErrors() == false);
        assertTrue(validator.validate(jwtClaims(Map.of(
                "iss", "http://localhost:8080",
                "aud", List.of("sample-resource-api"),
                "token_use", "id_token"))).hasErrors());
        assertTrue(validator.validate(jwtClaims(Map.of(
                "iss", "http://localhost:8080",
                "aud", List.of("sample-resource-api"),
                "token_use", "first_party_access"))).hasErrors());
        assertTrue(validator.validate(jwtClaims(Map.of(
                "iss", "http://localhost:8080",
                "aud", List.of("other-api"),
                "token_use", "oauth_access"))).hasErrors());
        assertTrue(validator.validate(jwtClaims(Map.of(
                "iss", "https://issuer.example.invalid",
                "aud", List.of("sample-resource-api"),
                "token_use", "oauth_access"))).hasErrors());
    }

    @Test
    void sampleEndpointsUseOauthScopeAndNeverTreatTenantAsOrganizationAuthorization() throws Exception {
        mockMvc.perform(get("/sample/me").with(jwt().jwt(token -> token
                        .subject("user-1")
                        .claim("tenant_id", "tenant-a")
                        .claim("client_id", "sample-resource-api")
                        .claim("scope", "openid email")
                        .claim("token_use", "oauth_access"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenant_id").value("tenant-a"));

        mockMvc.perform(get("/sample/protected").with(jwt().jwt(token -> token
                        .subject("user-1")
                        .claim("tenant_id", "tenant-a")
                        .claim("scope", "openid email sample.read")
                        .claim("token_use", "oauth_access"))))
                .andExpect(status().isOk());

        mockMvc.perform(get("/sample/protected").with(jwt().jwt(token -> token
                        .subject("user-1")
                        .claim("tenant_id", "tenant-a")
                        .claim("scope", "openid email")
                        .claim("token_use", "oauth_access"))))
                .andExpect(status().isForbidden());
    }

    private Jwt jwtClaims(Map<String, Object> claims) {
        Instant now = Instant.now();
        return new Jwt(
                "token",
                now,
                now.plusSeconds(300),
                Map.of("alg", "RS256", "kid", "authkit-key-1"),
                claims);
    }
}
