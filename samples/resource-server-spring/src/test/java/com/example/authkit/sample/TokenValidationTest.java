package com.example.authkit.sample;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
                "sub", "user-1",
                "jti", "token-1",
                "tenant_id", "tenant-a",
                "client_id", "sample-resource-api",
                "scope", "openid email",
                "amr", List.of("pwd")))).hasErrors() == false);
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

        Map<String, Object> complete = Map.of(
                "iss", "http://localhost:8080", "aud", List.of("sample-resource-api"),
                "token_use", "oauth_access", "sub", "user-1", "jti", "token-1",
                "tenant_id", "tenant-a", "client_id", "sample-resource-api",
                "scope", "openid email", "amr", List.of("pwd"));
        var extraAudience = new java.util.HashMap<>(complete);
        extraAudience.put("aud", List.of("sample-resource-api", "unexpected-api"));
        assertTrue(validator.validate(jwtClaims(extraAudience)).hasErrors());
        for (String required : List.of("sub", "jti", "tenant_id", "client_id", "scope", "amr")) {
            var missing = new java.util.HashMap<>(complete);
            missing.remove(required);
            assertTrue(validator.validate(jwtClaims(missing)).hasErrors(), () -> "accepted missing " + required);
        }
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

    @Test
    void actualDecoderChecksSignatureKidExpiryIssuerAudienceAndRequiredClaims() throws Exception {
        var key = new com.nimbusds.jose.jwk.gen.RSAKeyGenerator(2048).keyID("sample-proof-key").generate();
        var server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/jwks", exchange -> {
            byte[] body = new com.nimbusds.jose.jwk.JWKSet(key.toPublicJWK()).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (var stream = exchange.getResponseBody()) { stream.write(body); }
        });
        server.start();
        try {
            var decoder = new SecurityConfig().jwtDecoder("http://localhost:8080",
                    "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks", "sample-resource-api", "oauth_access");
            var complete = new java.util.HashMap<String, Object>();
            complete.put("iss", "http://localhost:8080"); complete.put("sub", "user-1");
            complete.put("aud", List.of("sample-resource-api")); complete.put("jti", "token-1");
            complete.put("tenant_id", "tenant-a"); complete.put("amr", List.of("pwd"));
            complete.put("client_id", "sample-resource-api"); complete.put("scope", "openid email");
            complete.put("token_use", "oauth_access"); complete.put("exp", Instant.now().plusSeconds(300).getEpochSecond());
            assertEquals("user-1", decoder.decode(signed(key, key.getKeyID(), complete)).getSubject());
            assertThrows(org.springframework.security.oauth2.jwt.JwtException.class,
                    () -> decoder.decode(signed(key, "unknown-kid", complete)));
            var attacker = new com.nimbusds.jose.jwk.gen.RSAKeyGenerator(2048).keyID(key.getKeyID()).generate();
            assertThrows(org.springframework.security.oauth2.jwt.JwtException.class,
                    () -> decoder.decode(signed(attacker, key.getKeyID(), complete)));
            for (String invalid : List.of("expiry", "exp", "issuer", "audience", "use", "sub", "jti", "tenant_id", "amr", "client_id", "scope")) {
                var claims = new java.util.HashMap<>(complete);
                switch (invalid) {
                    case "expiry" -> claims.put("exp", Instant.now().minusSeconds(300).getEpochSecond());
                    case "issuer" -> claims.put("iss", "https://wrong.example.test");
                    case "audience" -> claims.put("aud", List.of("sample-resource-api", "extra"));
                    case "use" -> claims.put("token_use", "id_token");
                    default -> claims.remove(invalid);
                }
                assertThrows(org.springframework.security.oauth2.jwt.JwtException.class,
                        () -> decoder.decode(signed(key, key.getKeyID(), claims)), invalid);
            }
        } finally {
            server.stop(0);
        }
    }

    private String signed(com.nimbusds.jose.jwk.RSAKey key, String kid, Map<String, Object> claims) throws Exception {
        var token = new com.nimbusds.jwt.SignedJWT(new com.nimbusds.jose.JWSHeader.Builder(
                com.nimbusds.jose.JWSAlgorithm.RS256).keyID(kid).build(), com.nimbusds.jwt.JWTClaimsSet.parse(claims));
        token.sign(new com.nimbusds.jose.crypto.RSASSASigner(key));
        return token.serialize();
    }

    private Jwt jwtClaims(Map<String, Object> claims) {
        Instant now = Instant.now();
        var timedClaims = new java.util.HashMap<>(claims);
        timedClaims.put("exp", now.plusSeconds(300));
        return new Jwt(
                "token",
                now,
                now.plusSeconds(300),
                Map.of("alg", "RS256", "kid", "authkit-key-1"),
                timedClaims);
    }
}
