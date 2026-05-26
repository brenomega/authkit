package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthClient;
import io.github.brenomega.authkit.domain.user.dto.OAuthAuthorizeRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.InvalidOAuthRequestException;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
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
                authz.code(),
                "https://client.example/callback",
                client.getClientId(),
                null,
                verifier);

        assertNotNull(tokens.accessToken());
        assertNotNull(tokens.idToken());
        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.token(
                "authorization_code",
                authz.code(),
                "https://client.example/callback",
                client.getClientId(),
                null,
                verifier));
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
}
