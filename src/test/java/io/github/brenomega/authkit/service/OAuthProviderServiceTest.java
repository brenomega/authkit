package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import io.github.brenomega.authkit.domain.oauth.entity.OAuthClient;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.InvalidOAuthRequestException;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class OAuthProviderServiceTest {

    @Autowired
    private OAuthProviderService oauthProviderService;

    @Autowired
    private OAuthClientRepository oauthClientRepository;

    @Autowired
    private OAuthConsentRepository oauthConsentRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @DisplayName("Issues and consumes authorization-code + PKCE tokens for OIDC client")
    void authorizationCodeWithPkceIssuesTokensAndIsOneTimeUse() throws Exception {
        User user = confirmedUser("oidc-user@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                user.getTenantId(),
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
                user.getTenantId(),
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
                user.getTenantId(),
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
    @DisplayName("OAuth authorize rejects redirect mismatch, tenant mismatch, and missing consent")
    void authorize_rejectsPolicyBypassAttempts() throws Exception {
        User user = confirmedUser("oidc-policy@example.com");
        User otherTenantUser = confirmedUser("oidc-policy-other@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                otherTenantUser.getTenantId(),
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
        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest(
                "code", client.getClientId(), "https://client.example/callback", "openid", null, challenge, "S256", null, true)));
        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.authorize(jwt(otherTenantUser), new OAuthAuthorizeRequest(
                "code", client.getClientId(), "https://client.example/callback", "openid email", null, challenge, "S256", null, false)));
    }

    @Test
    @DisplayName("OAuth token exchange validates PKCE verifier format and consumes codes atomically")
    void token_rejectsInvalidPkceAndConcurrentReplay() throws Exception {
        User user = confirmedUser("oidc-concurrent@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                user.getTenantId(),
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
    @DisplayName("OAuth revocation, introspection, and userinfo honor client-scoped tokens")
    void revocationIntrospectionAndUserinfo() throws Exception {
        User user = confirmedUser("oidc-userinfo@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                user.getTenantId(),
                "client-userinfo",
                null,
                true,
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
                null,
                verifier);

        assertEquals(true, oauthProviderService
                .introspect(tokens.accessToken(), "access_token", client.getClientId(), null)
                .get("active"));
        assertEquals(user.getEmail(), oauthProviderService.userInfo(tokens.accessToken()).get("email"));

        oauthProviderService.revoke(tokens.accessToken(), "access_token", client.getClientId(), null);

        assertEquals(false, oauthProviderService
                .introspect(tokens.accessToken(), "access_token", client.getClientId(), null)
                .get("active"));
        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.userInfo(tokens.accessToken()));
    }

    private User confirmedUser(String email) {
        User user = new User(email, "hash", "Test User", null, true, true, "token");
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
        String query = URI.create(redirectUri).getRawQuery();
        return Arrays.stream(query.split("&"))
                .map(part -> part.split("=", 2))
                .filter(parts -> parts.length == 2 && "code".equals(parts[0]))
                .map(parts -> URLDecoder.decode(parts[1], StandardCharsets.UTF_8))
                .findFirst()
                .orElseThrow();
    }
}
