package io.github.brenomega.authkit.infrastructure.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.hamcrest.Matchers.containsString;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import io.github.brenomega.authkit.infrastructure.network.rateLimit.RateLimitingFilter;
import jakarta.servlet.Filter;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Autowired
    private FilterChainProxy filterChainProxy;

    @Autowired
    private JwtEncoder jwtEncoder;

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
                        .header("CF-Connecting-IP", "127.0.0.15") // avoid cache constraints from tests
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

    @Test
    @DisplayName("Bearer JWT with unexpected issuer is rejected")
    void bearerJwtWithUnexpectedIssuer_returns401() throws Exception {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("unexpected-issuer")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .subject(UUID.randomUUID().toString())
                .build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        mockMvc.perform(get("/api/v1/users/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errors[0]").value("Unauthorized"));
    }

    @Test
    @DisplayName("Bearer JWT without required audience is rejected")
    void bearerJwtWithoutAudience_returns401() throws Exception {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("authkit")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .subject(UUID.randomUUID().toString())
                .build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        mockMvc.perform(get("/api/v1/users/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errors[0]").value("Unauthorized"));
    }

    @Test
    @DisplayName("JWKS endpoint exposes the configured public signing key metadata")
    void jwksEndpoint_exposesConfiguredSigningKey() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value("authkit-key-1"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"));
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

    @SuppressWarnings("null")
    @Test
    @DisplayName("Secure responses include HSTS")
    void securityHeader_hsts() throws Exception {
        mockMvc.perform(get("/api/v1/anything").secure(true))
                .andExpect(header().string("Strict-Transport-Security", containsString("max-age=31536000")))
                .andExpect(header().string("Strict-Transport-Security", containsString("includeSubDomains")))
                .andExpect(header().string("Strict-Transport-Security", containsString("preload")));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Responses include strict API Content-Security-Policy")
    void securityHeader_contentSecurityPolicy() throws Exception {
        mockMvc.perform(get("/api/v1/anything"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")));
    }

    @Test
    @DisplayName("Responses include no-referrer policy for recovery-token leakage resistance")
    void securityHeader_referrerPolicy() throws Exception {
        mockMvc.perform(get("/api/v1/anything"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
    }

    @Test
    @DisplayName("CORS preflight only allows configured origins")
    void corsPreflight_allowsConfiguredOrigin() throws Exception {
        mockMvc.perform(options("/api/v1/auth/login")
                        .header("Origin", "http://localhost:3000")
                        .header("Access-Control-Request-Method", "POST"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:3000"))
                .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Oversized request bodies are rejected before controller parsing")
    void requestBodyLimit_rejectsOversizedPayload() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content("A".repeat(65537)))
                .andExpect(status().isPayloadTooLarge())
                .andExpect(jsonPath("$.errors[0]").value("Request body too large"));
    }

    // -------------------------------------------------------------------------
    // Filter Chain Order (DT 3.2.12)
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Security filter chain follows DT 3.2.12 specific order")
    void securityFilterChain_followsDT3212Order() {
        List<SecurityFilterChain> filterChains = filterChainProxy.getFilterChains();
        // Assuming the main API chain is the first or only one containing BearerTokenAuthenticationFilter
        SecurityFilterChain targetChain = filterChains.get(0);
        List<Filter> filters = targetChain.getFilters();

        int rateLimitingIndex = -1;
        int requestBodySizeIndex = -1;
        int bearerIndex = -1;
        int workerIndex = -1;
        int userAuthIndex = -1;
        int authorizationIndex = -1;

        for (int i = 0; i < filters.size(); i++) {
            Filter f = filters.get(i);
            if (f instanceof RateLimitingFilter) rateLimitingIndex = i;
            else if (f instanceof RequestBodySizeLimitFilter) requestBodySizeIndex = i;
            else if (f instanceof BearerTokenAuthenticationFilter) bearerIndex = i;
            else if (f instanceof WorkerAuthFilter) workerIndex = i;
            else if (f instanceof UserAuthoritiesFilter) userAuthIndex = i;
            else if (f instanceof AuthorizationFilter) authorizationIndex = i;
        }

        assertTrue(rateLimitingIndex != -1, "RateLimitingFilter must be in the chain");
        assertTrue(requestBodySizeIndex != -1, "RequestBodySizeLimitFilter must be in the chain");
        assertTrue(bearerIndex != -1, "BearerTokenAuthenticationFilter must be in the chain");
        assertTrue(workerIndex != -1, "WorkerAuthFilter must be in the chain");
        assertTrue(userAuthIndex != -1, "UserAuthoritiesFilter must be in the chain");
        assertTrue(authorizationIndex != -1, "AuthorizationFilter must be in the chain");

        assertTrue(rateLimitingIndex < bearerIndex, "RateLimitingFilter must precede BearerTokenAuthenticationFilter");
        assertTrue(rateLimitingIndex < requestBodySizeIndex, "RateLimitingFilter must precede RequestBodySizeLimitFilter");
        assertTrue(requestBodySizeIndex < bearerIndex, "RequestBodySizeLimitFilter must precede BearerTokenAuthenticationFilter");
        assertTrue(bearerIndex < workerIndex, "BearerTokenAuthenticationFilter must precede WorkerAuthFilter");
        assertTrue(workerIndex < userAuthIndex, "WorkerAuthFilter must precede UserAuthoritiesFilter");
        assertTrue(userAuthIndex < authorizationIndex, "UserAuthoritiesFilter must precede AuthorizationFilter");
    }
}
