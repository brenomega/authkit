package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

import io.github.brenomega.authkit.domain.oauth.dto.OAuthAuthorizeRequest;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthAuthorizationCode;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthClient;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.exception.InvalidOAuthRequestException;
import io.github.brenomega.authkit.exception.OAuthProtocolException;
import io.github.brenomega.authkit.exception.OAuthRefreshReplayException;
import io.github.brenomega.authkit.repository.OAuthAuthorizationCodeRepository;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class OAuthProviderServiceTest {

    @Autowired
    private OAuthProviderService oauthProviderService;

    @Autowired
    private OAuthClientRepository oauthClientRepository;

    @Autowired
    private OAuthConsentRepository oauthConsentRepository;

    @Autowired
    private OAuthAuthorizationCodeRepository authorizationCodeRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Issues and consumes authorization-code + PKCE tokens for OIDC client")
    void authorizationCodeWithPkceIssuesTokensAndIsOneTimeUse() throws Exception {
        User user = confirmedUser("oidc-user@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-test",
                null,
                true,
                "Client Test",
                Set.of("https://client.example/callback"),
                Set.of("openid", "email", "profile"),
                true,
                java.time.Instant.now()));

        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        String challenge = pkceChallenge(verifier);

        var authz = oauthProviderService.authorize(
                jwt(user),
                new OAuthAuthorizeRequest(
                        "code",
                        client.getClientId(),
                        "https://client.example/callback",
                        "openid email",
                        "state-1",
                        challenge,
                        "S256",
                        "nonce-1",
                        true));

        assertNotNull(oauthConsentRepository
                .findByUserIdAndClientIdAndRevokedAtIsNull(user.getId(), client.getClientId())
                .orElse(null));

        var tokens = oauthProviderService.token(
                "authorization_code",
                codeFrom(authz.redirectUri()),
                "https://client.example/callback",
                client.getClientId(),
                null,
                verifier);

        assertNotNull(tokens.accessToken());
        assertNotNull(tokens.idToken());
        assertEquals("oauth_access", tokenClaim(tokens.accessToken(), "token_use"));
        assertEquals("id_token", tokenClaim(tokens.idToken(), "token_use"));
        assertThrows(JwtException.class, () -> jwtDecoder.decode(tokens.accessToken()));
        assertThrows(JwtException.class, () -> jwtDecoder.decode(tokens.idToken()));
        mockMvc.perform(get("/api/v1/users/me")
                        .header("Authorization", "Bearer " + tokens.accessToken()))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/users/me")
                        .header("Authorization", "Bearer " + tokens.idToken()))
                .andExpect(status().isUnauthorized());
        assertThrows(OAuthProtocolException.class, () -> oauthProviderService
                .introspect(tokens.idToken(), "access_token", client.getClientId(), null));
        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.userInfo(tokens.idToken()));
        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.token(
                "authorization_code",
                codeFrom(authz.redirectUri()),
                "https://client.example/callback",
                client.getClientId(),
                null,
                verifier));
    }

    @Test
    @DisplayName("Confidential OAuth clients require their slow-hashed client secret")
    void confidentialClient_requiresSlowHashedSecret() throws Exception {
        User user = confirmedUser("oidc-confidential@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-confidential",
                passwordEncoder.encode("client-secret-value"),
                false,
                "Confidential Client",
                Set.of("https://confidential.example/callback"),
                Set.of("openid", "email"),
                true,
                java.time.Instant.now()));

        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        var authz = oauthProviderService.authorize(
                jwt(user),
                new OAuthAuthorizeRequest(
                        "code",
                        client.getClientId(),
                        "https://confidential.example/callback",
                        "openid email",
                        "state-2",
                        pkceChallenge(verifier),
                        "S256",
                        "nonce-2",
                        true));

        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.token(
                "authorization_code",
                codeFrom(authz.redirectUri()),
                "https://confidential.example/callback",
                client.getClientId(),
                "wrong-secret",
                verifier));

        var tokens = oauthProviderService.token(
                "authorization_code",
                codeFrom(authz.redirectUri()),
                "https://confidential.example/callback",
                client.getClientId(),
                "client-secret-value",
                verifier);

        assertNotNull(tokens.accessToken());
        assertNotNull(tokens.idToken());
    }

    @Test
    @DisplayName("Authorize response does not expose raw code outside redirect URI")
    void authorize_doesNotExposeRawCodeField() throws Exception {
        User user = confirmedUser("oidc-no-leak@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-no-leak",
                null,
                true,
                "No Leak Client",
                Set.of("https://client.example/callback"),
                Set.of("openid"),
                true,
                java.time.Instant.now()));

        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        var authz = oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest(
                "code",
                client.getClientId(),
                "https://client.example/callback",
                "openid",
                "state-no-leak",
                pkceChallenge(verifier),
                "S256",
                null,
                true));

        assertTrue(authz.redirectUri().contains("code="));
        assertFalse(Arrays.stream(authz.getClass().getRecordComponents())
                .anyMatch(component -> "code".equals(component.getName())));
    }

    @Test
    @DisplayName("OAuth authorize rejects redirect mismatch and missing consent for global clients")
    void authorize_rejectsPolicyBypassAttempts() throws Exception {
        User user = confirmedUser("oidc-policy@example.com");
        User otherTenantUser = confirmedUser("oidc-policy-other@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-policy",
                null,
                true,
                "Policy Client",
                Set.of("https://client.example/callback"),
                Set.of("openid", "email"),
                true,
                java.time.Instant.now()));

        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        String challenge = pkceChallenge(verifier);

        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest(
                "code", client.getClientId(), "https://evil.example/callback", "openid", null, challenge, "S256", null, true)));
        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.authorize(jwt(otherTenantUser), new OAuthAuthorizeRequest(
                "code", client.getClientId(), "https://client.example/callback", "openid email", null, challenge, "S256", null, false)));
    }

    @Test
    @DisplayName("OAuth token exchange validates PKCE verifier format and consumes codes atomically")
    void token_rejectsInvalidPkceAndConcurrentReplay() throws Exception {
        User user = confirmedUser("oidc-concurrent@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-concurrent",
                null,
                true,
                "Concurrent Client",
                Set.of("https://client.example/callback"),
                Set.of("openid"),
                true,
                java.time.Instant.now()));
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        var authz = oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest(
                "code", client.getClientId(), "https://client.example/callback", "openid", null,
                pkceChallenge(verifier), "S256", null, true));
        String code = codeFrom(authz.redirectUri());

        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.token(
                "authorization_code", code, "https://client.example/callback", client.getClientId(), null, "short"));

        var secondAuthz = oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest(
                "code", client.getClientId(), "https://client.example/callback", "openid", null,
                pkceChallenge(verifier), "S256", null, true));
        String concurrentCode = codeFrom(secondAuthz.redirectUri());

        var executor = Executors.newFixedThreadPool(2);
        try {
            Callable<Boolean> exchange = () -> {
                try {
                    oauthProviderService.token(
                            "authorization_code",
                            concurrentCode,
                            "https://client.example/callback",
                            client.getClientId(),
                            null,
                            verifier);
                    return true;
                } catch (InvalidOAuthRequestException ex) {
                    return false;
                }
            };
            var results = executor.invokeAll(java.util.List.of(exchange, exchange));
            long successes = results.stream().filter(result -> {
                try {
                    return result.get();
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }).count();
            assertEquals(1, successes);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("OAuth token exchange rejects an expired authorization code")
    void tokenRejectsExpiredAuthorizationCode() throws Exception {
        User user = confirmedUser("oidc-expired-code@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-expired-code",
                null,
                true,
                "Expired Code Client",
                Set.of("https://client.example/callback"),
                Set.of("openid"),
                true,
                java.time.Instant.now()));
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        String rawCode = "expired-" + java.util.UUID.randomUUID();
        authorizationCodeRepository.save(new OAuthAuthorizationCode(
                TokenHasher.sha256Hex(rawCode),
                client.getClientId(),
                user.getId(),
                user.getTenantId(),
                "https://client.example/callback",
                Set.of("openid"),
                Set.of("pwd"),
                pkceChallenge(verifier),
                "S256",
                null,
                java.time.Instant.now().minusSeconds(600),
                java.time.Instant.now().minusSeconds(1)));

        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.token(
                "authorization_code",
                rawCode,
                "https://client.example/callback",
                client.getClientId(),
                null,
                verifier));
    }

    @Test
    @DisplayName("OAuth revocation, introspection, and userinfo honor client-scoped tokens")
    void revocationIntrospectionAndUserinfo() throws Exception {
        User user = confirmedUser("oidc-userinfo@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-userinfo",
                passwordEncoder.encode("userinfo-secret"),
                false,
                "Userinfo Client",
                Set.of("https://client.example/callback"),
                Set.of("openid", "email", "profile"),
                true,
                java.time.Instant.now()));
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        var authz = oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest(
                "code", client.getClientId(), "https://client.example/callback", "openid email profile", null,
                pkceChallenge(verifier), "S256", null, true));
        var tokens = oauthProviderService.token(
                "authorization_code",
                codeFrom(authz.redirectUri()),
                "https://client.example/callback",
                client.getClientId(),
                "userinfo-secret",
                verifier);

        OAuthClient otherClient = oauthClientRepository.save(new OAuthClient(
                "client-other-audience",
                passwordEncoder.encode("other-secret"),
                false,
                "Other Audience Client",
                Set.of("https://other.example/callback"),
                Set.of("openid"),
                true,
                java.time.Instant.now()));

        assertEquals(true, oauthProviderService
                .introspect(tokens.accessToken(), "access_token", client.getClientId(), "userinfo-secret")
                .get("active"));
        assertEquals(false, oauthProviderService
                .introspect(tokens.accessToken(), "access_token", otherClient.getClientId(), "other-secret")
                .get("active"));
        assertEquals(user.getEmail(), oauthProviderService.userInfo(tokens.accessToken()).get("email"));

        oauthProviderService.revoke(tokens.accessToken(), "access_token", client.getClientId(), "userinfo-secret");

        assertEquals(false, oauthProviderService
                .introspect(tokens.accessToken(), "access_token", client.getClientId(), "userinfo-secret")
                .get("active"));
        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.userInfo(tokens.accessToken()));
    }

    @Test
    @DisplayName("Conventional authorize uses a signed one-time server-side transaction")
    void conventionalAuthorizeIsResumableAndOneTime() throws Exception {
        User user = confirmedUser("oidc-browser@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-browser", null, true, "Browser Client",
                Set.of("https://client.example/callback"), Set.of("openid", "profile"), true,
                java.time.Instant.now()));
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

        String loginLocation = oauthProviderService.beginAuthorization(
                "code", client.getClientId(), "https://client.example/callback", "openid profile",
                "browser-state", pkceChallenge(verifier), "S256", "browser-nonce");
        String transaction = queryParameter(loginLocation, "transaction");

        var details = oauthProviderService.authorizationTransaction(transaction, jwt(user));
        assertEquals(client.getClientId(), details.clientId());
        assertTrue(details.consentRequired());
        String callback = oauthProviderService.resumeAuthorization(transaction, jwt(user), true);
        assertEquals("browser-state", queryParameter(callback, "state"));
        assertNotNull(queryParameter(callback, "code"));
        assertThrows(OAuthProtocolException.class,
                () -> oauthProviderService.resumeAuthorization(transaction, jwt(user), true));
    }

    @Test
    @DisplayName("Opaque OAuth refresh tokens rotate and replay revokes the entire family")
    void refreshRotationAndReplayRevokesFamilyAndAccess() throws Exception {
        User user = confirmedUser("oidc-refresh@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-refresh", passwordEncoder.encode("refresh-secret"), false, "Refresh Client",
                Set.of("https://client.example/callback"), Set.of("openid", "offline_access"), true,
                java.time.Instant.now()));
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        var authz = oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest(
                "code", client.getClientId(), "https://client.example/callback", "openid offline_access",
                "refresh-state", pkceChallenge(verifier), "S256", "refresh-nonce", true));
        var initial = oauthProviderService.token("authorization_code", codeFrom(authz.redirectUri()),
                "https://client.example/callback", client.getClientId(), "refresh-secret", verifier);
        assertNotNull(initial.refreshToken());
        assertFalse(initial.refreshToken().contains("."), "refresh token must be opaque, not a JWT");

        var rotated = oauthProviderService.token("refresh_token", null, null, client.getClientId(),
                "refresh-secret", null, initial.refreshToken());
        assertNotNull(rotated.refreshToken());
        assertFalse(initial.refreshToken().equals(rotated.refreshToken()));
        assertEquals(true, oauthProviderService.introspect(rotated.accessToken(), "access_token",
                client.getClientId(), "refresh-secret").get("active"));

        assertThrows(OAuthRefreshReplayException.class, () -> oauthProviderService.token(
                "refresh_token", null, null, client.getClientId(), "refresh-secret", null,
                initial.refreshToken()));
        assertEquals(false, oauthProviderService.introspect(rotated.accessToken(), "access_token",
                client.getClientId(), "refresh-secret").get("active"));
        assertEquals(false, oauthProviderService.introspect(rotated.refreshToken(), "refresh_token",
                client.getClientId(), "refresh-secret").get("active"));
    }

    @Test
    @DisplayName("Concurrent refresh has one rotation winner and replay leaves the family revoked")
    void concurrentRefreshHasOneWinnerAndRevokesFamily() throws Exception {
        User user = confirmedUser("oidc-refresh-concurrent@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-refresh-concurrent", passwordEncoder.encode("concurrent-secret"), false,
                "Concurrent Refresh Client", Set.of("https://client.example/callback"),
                Set.of("offline_access"), true, java.time.Instant.now()));
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        var authz = oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest(
                "code", client.getClientId(), "https://client.example/callback", "offline_access",
                "concurrent-state", pkceChallenge(verifier), "S256", null, true));
        var initial = oauthProviderService.token("authorization_code", codeFrom(authz.redirectUri()),
                "https://client.example/callback", client.getClientId(), "concurrent-secret", verifier);

        var executor = Executors.newFixedThreadPool(2);
        try {
            Callable<Boolean> rotate = () -> {
                try {
                    oauthProviderService.token("refresh_token", null, null, client.getClientId(),
                            "concurrent-secret", null, initial.refreshToken());
                    return true;
                } catch (OAuthProtocolException ex) {
                    return false;
                }
            };
            var results = executor.invokeAll(java.util.List.of(rotate, rotate));
            long successes = results.stream().filter(result -> {
                try {
                    return result.get();
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }).count();
            assertEquals(1, successes);
            assertEquals(false, oauthProviderService.introspect(initial.refreshToken(), "refresh_token",
                    client.getClientId(), "concurrent-secret").get("active"));
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    @DisplayName("OAuth HTTP endpoints use conventional redirects and standard unwrapped errors")
    void oauthHttpWireContractIsStandard() throws Exception {
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-http-wire", null, true, "HTTP Wire Client",
                Set.of("https://client.example/callback"), Set.of("openid"), true,
                java.time.Instant.now()));
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", client.getClientId())
                        .param("redirect_uri", "https://client.example/callback")
                        .param("scope", "openid")
                        .param("state", "http-state")
                        .param("nonce", "http-nonce")
                        .param("code_challenge", pkceChallenge(verifier))
                        .param("code_challenge_method", "S256"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", org.hamcrest.Matchers.startsWith(
                        "http://localhost:3000/oauth/authorize?transaction=")));

        mockMvc.perform(post("/oauth2/token")
                        .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("client_id", client.getClientId()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"))
                .andExpect(jsonPath("$.error_description").isString())
                .andExpect(jsonPath("$.data").doesNotExist());
    }

    private User confirmedUser(String email) {
        User user = new User(email, "hash", "Test User", true, true, "token");
        user.setEmailConfirmed(true);
        return userRepository.save(user);
    }

    private Jwt jwt(User user) {
        return new Jwt(
                "token",
                java.time.Instant.now(),
                java.time.Instant.now().plusSeconds(900),
                Map.of("alg", "none"),
                Map.of("sub", user.getId().toString(), "tenant_id", user.getTenantId().toString(), "amr", java.util.List.of("pwd")));
    }

    private String pkceChallenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private String codeFrom(String redirectUri) {
        return queryParameter(redirectUri, "code");
    }

    private String queryParameter(String uri, String name) {
        String query = URI.create(uri).getRawQuery();
        return Arrays.stream(query.split("&"))
                .map(part -> part.split("=", 2))
                .filter(parts -> parts.length == 2 && name.equals(parts[0]))
                .map(parts -> URLDecoder.decode(parts[1], StandardCharsets.UTF_8))
                .findFirst()
                .orElseThrow();
    }

    private String tokenClaim(String token, String claim) throws Exception {
        String payload = token.split("\\.")[1];
        return objectMapper.readTree(Base64.getUrlDecoder().decode(payload)).get(claim).asText();
    }
}
