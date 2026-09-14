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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import io.github.brenomega.authkit.domain.oauth.dto.OAuthAuthorizeRequest;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthAuthorizationCode;
import io.github.brenomega.authkit.domain.oauth.entity.OAuthClient;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.exception.InvalidOAuthRequestException;
import io.github.brenomega.authkit.exception.OAuthProtocolException;
import io.github.brenomega.authkit.exception.OAuthRefreshReplayException;
import io.github.brenomega.authkit.repository.OAuthAuthorizationCodeRepository;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.domain.user.dto.AdminAccountStateRequest;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.enums.Role;
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
import org.testcontainers.junit.jupiter.Testcontainers;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.github.brenomega.authkit.support.PostgresIntegrationTestSupport;
import io.github.brenomega.authkit.service.spi.TokenStorage;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = false)
class OAuthProviderServiceTest extends PostgresIntegrationTestSupport {

    @Autowired
    private OAuthProviderService oauthProviderService;

    @Autowired
    private AuthService authService;

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

    @Autowired
    private AdminService adminService;

    @Autowired
    private AccountLifecycleService accountLifecycleService;

    @Autowired
    private PasskeyCredentialRepository passkeyCredentialRepository;

    @Autowired
    private EmailChangeService emailChangeService;

    @Autowired
    private TokenStorage tokenStorage;

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
                Instant.now()));

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
                Instant.now()));

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
                Instant.now()));

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
                Instant.now()));

        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        String challenge = pkceChallenge(verifier);

        assertThrows(
                InvalidOAuthRequestException.class,
                () -> oauthProviderService.authorize(
                        jwt(user),
                        new OAuthAuthorizeRequest(
                                "code",
                                client.getClientId(),
                                "https://evil.example/callback",
                                "openid",
                                null,
                                challenge,
                                "S256",
                                null,
                                true)));
        assertThrows(
                InvalidOAuthRequestException.class,
                () -> oauthProviderService.authorize(
                        jwt(otherTenantUser),
                        new OAuthAuthorizeRequest(
                                "code",
                                client.getClientId(),
                                "https://client.example/callback",
                                "openid email",
                                null,
                                challenge,
                                "S256",
                                null,
                                false)));
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
                Instant.now()));
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
            var results = executor.invokeAll(List.of(exchange, exchange));
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
                Instant.now()));
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        String rawCode = "expired-" + UUID.randomUUID();
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
                Instant.now().minusSeconds(600),
                Instant.now().minusSeconds(1)));

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
                Instant.now()));
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
                Instant.now()));

        assertEquals(true, oauthProviderService
                .introspect(tokens.accessToken(), "access_token", client.getClientId(), "userinfo-secret")
                .get("active"));
        assertEquals(false, oauthProviderService
                .introspect(tokens.accessToken(), "access_token", otherClient.getClientId(), "other-secret")
                .get("active"));
        assertEquals(user.getEmail(), oauthProviderService.userInfo(tokens.accessToken()).get("email"));
        mockMvc.perform(get("/oauth2/userinfo")
                        .header("Authorization", "bEaReR " + tokens.accessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(user.getEmail()));
        mockMvc.perform(get("/oauth2/userinfo")
                        .header("Authorization", "Bearer " + tokens.idToken()))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate",
                        org.hamcrest.Matchers.containsString("Bearer")));
        String firstParty = authService.issueLoginForVerifiedUser(user, List.of("pwd"), "userinfo_cross_token")
                .response().accessToken();
        mockMvc.perform(get("/oauth2/userinfo")
                        .header("Authorization", "Bearer " + firstParty))
                .andExpect(status().isUnauthorized());

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
                Instant.now()));
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
    void registeredRedirectWithExistingQueryReceivesOauthParametersInItsQuery() throws Exception {
        User user = confirmedUser("oidc-query-redirect@example.com");
        String redirect = "https://client.example/callback?channel=mobile";
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-query-redirect", null, true, "Query Redirect Client",
                Set.of(redirect), Set.of("openid"), true, Instant.now()));
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

        var result = oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest(
                "code", client.getClientId(), redirect, "openid", "bound-state",
                pkceChallenge(verifier), "S256", "bound-nonce", true));

        assertEquals("mobile", queryParameter(result.redirectUri(), "channel"));
        assertEquals("bound-state", queryParameter(result.redirectUri(), "state"));
        assertFalse(queryParameter(result.redirectUri(), "code").isBlank());
        assertEquals(null, URI.create(result.redirectUri()).getFragment());
    }

    @Test
    @DisplayName("Opaque OAuth refresh tokens rotate and replay revokes the entire family")
    void refreshRotationAndReplayRevokesFamilyAndAccess() throws Exception {
        User user = confirmedUser("oidc-refresh@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-refresh", passwordEncoder.encode("refresh-secret"), false, "Refresh Client",
                Set.of("https://client.example/callback"), Set.of("openid", "offline_access"), true,
                Instant.now()));
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
                Set.of("offline_access"), true, Instant.now()));
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
            var results = executor.invokeAll(List.of(rotate, rotate));
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
    @DisplayName("Suspension and deletion invalidate OAuth access/refresh without reactivation resurrection")
    void lifecycleTransitionsInvalidateOAuthTokensDurably() throws Exception {
        User target = confirmedUser("oauth-lifecycle-target@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-lifecycle", passwordEncoder.encode("lifecycle-secret"), false, "Lifecycle Client",
                Set.of("https://client.example/callback"), Set.of("openid", "offline_access"), true,
                Instant.now()));
        var tokens = issueOfflineTokens(target, client, "lifecycle-secret", "lifecycle-state");

        User admin = new User("oauth-lifecycle-admin@example.com", passwordEncoder.encode("AdminPassword123!"),
                "Admin", true, true, null);
        admin.setEmailConfirmed(true);
        admin.setRole(Role.PLATFORM_ADMIN);
        admin = userRepository.saveAndFlush(admin);
        passkeyCredentialRepository.saveAndFlush(new PasskeyCredential(
                admin.getId(), admin.getTenantId(), "oauth-lifecycle-admin-key", "public-key", 0,
                "internal", "Admin key", true, Instant.now()));
        Jwt adminJwt = Jwt.withTokenValue("admin")
                .header("alg", "RS256")
                .subject(admin.getId().toString())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("tenant_id", admin.getTenantId().toString())
                .claim("amr", List.of("pwd", "webauthn"))
                .build();

        adminService.suspendUser(adminJwt, target.getId(),
                new AdminAccountStateRequest("security response", "AdminPassword123!", null));
        assertInactive(tokens, client, "lifecycle-secret");

        adminService.reactivateUser(adminJwt, target.getId(),
                new AdminAccountStateRequest("review complete", "AdminPassword123!", null));
        assertInactive(tokens, client, "lifecycle-secret");

        User deletionTarget = confirmedUserWithPassword(
                "oauth-deletion-target@example.com", "DeletionPassword123!");
        var deletionTokens = issueOfflineTokens(
                deletionTarget, client, "lifecycle-secret", "deletion-state");
        accountLifecycleService.requestDeletion(
                deletionTarget.getId().toString(), new StepUpRequest("DeletionPassword123!"));
        assertInactive(deletionTokens, client, "lifecycle-secret");
    }

    @Test
    @DisplayName("Confirmed email replacement revokes first-party and OAuth renewable lineages")
    void emailChangeInvalidatesEveryOldRefreshLineage() throws Exception {
        User target = confirmedUser("email-lineage-old@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-email-lineage", passwordEncoder.encode("email-secret"), false, "Email Client",
                Set.of("https://client.example/callback"), Set.of("openid", "offline_access"), true,
                Instant.now()));
        var oauthTokens = issueOfflineTokens(target, client, "email-secret", "email-lineage-state");
        var firstParty = authService.issueLoginForVerifiedUser(target, List.of("pwd"), "email_lineage_proof");
        var firstPartyParsed = RefreshTokenCodec.parse(firstParty.refreshToken()).orElseThrow();
        long issuedSecurityVersion = tokenStorage.findSessionMetadata(
                target.getId().toString(), firstPartyParsed.jti()).orElseThrow().securityVersion();
        assertTrue(tokenStorage.validateToken(
                target.getId().toString(), firstPartyParsed.jti(), firstParty.refreshToken()));

        String rawEmailToken = "email-change-" + UUID.randomUUID();
        target.requestEmailChange("email-lineage-new@example.com", TokenHasher.sha256Hex(rawEmailToken),
                Instant.now(), Instant.now().plusSeconds(300));
        userRepository.saveAndFlush(target);
        emailChangeService.confirm(rawEmailToken);

        assertTrue(userRepository.findById(target.getId()).orElseThrow().getSecurityVersion()
                > issuedSecurityVersion);
        assertThrows(io.github.brenomega.authkit.exception.InvalidRefreshTokenException.class,
                () -> authService.refresh(firstParty.refreshToken()));
        assertInactive(oauthTokens, client, "email-secret");
    }

    @Test
    @DisplayName("Concurrent refresh and suspension cannot leave an OAuth lineage live")
    void concurrentRefreshAndSuspensionEndRevoked() throws Exception {
        User target = confirmedUser("oauth-lifecycle-race@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-lifecycle-race", passwordEncoder.encode("race-secret"), false, "Lifecycle Race",
                Set.of("https://client.example/callback"), Set.of("openid", "offline_access"), true,
                Instant.now()));
        var initial = issueOfflineTokens(target, client, "race-secret", "race-state");
        User admin = platformAdmin("oauth-lifecycle-race-admin@example.com", "RaceAdminPassword123!");
        Jwt adminJwt = freshAdminJwt(admin);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        AtomicReference<io.github.brenomega.authkit.domain.oauth.dto.OAuthTokenResponse> rotated =
                new AtomicReference<>();

        try (var executor = Executors.newFixedThreadPool(2)) {
            var refresh = executor.submit(() -> {
                ready.countDown();
                start.await(5, TimeUnit.SECONDS);
                try {
                    rotated.set(oauthProviderService.token("refresh_token", null, null,
                            client.getClientId(), "race-secret", null, initial.refreshToken()));
                } catch (OAuthProtocolException expected) {
                    // Suspension won the user-row race.
                }
                return null;
            });
            var suspend = executor.submit(() -> {
                ready.countDown();
                start.await(5, TimeUnit.SECONDS);
                adminService.suspendUser(adminJwt, target.getId(),
                        new AdminAccountStateRequest("concurrent response", "RaceAdminPassword123!", null));
                return null;
            });
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            refresh.get();
            suspend.get();
        }

        assertEquals(io.github.brenomega.authkit.domain.user.enums.AccountState.SUSPENDED,
                userRepository.findById(target.getId()).orElseThrow().getAccountState());
        assertInactive(initial, client, "race-secret");
        if (rotated.get() != null) {
            assertInactive(rotated.get(), client, "race-secret");
        }
    }

    @SuppressWarnings("null")
@Test
    @DisplayName("OAuth HTTP endpoints use conventional redirects and standard unwrapped errors")
    void oauthHttpWireContractIsStandard() throws Exception {
        OAuthClient client = oauthClientRepository.save(new OAuthClient(
                "client-http-wire", null, true, "HTTP Wire Client",
                Set.of("https://client.example/callback"), Set.of("openid"), true,
                Instant.now()));
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

        OAuthClient confidential = oauthClientRepository.save(new OAuthClient(
                "client-http-confidential", passwordEncoder.encode("wire-secret"), false,
                "HTTP Confidential", Set.of("https://client.example/callback"), Set.of("openid"), true,
                Instant.now()));
        String basic = Base64.getEncoder().encodeToString(
                (confidential.getClientId() + ":wire-secret").getBytes(StandardCharsets.UTF_8));
        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "bAsIc " + basic)
                        .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", "not-a-code")
                        .param("redirect_uri", "https://client.example/callback")
                        .param("code_verifier", verifier))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic !!!not-base64!!!")
                        .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(header().string("WWW-Authenticate",
                        org.hamcrest.Matchers.startsWith("Basic")));
        mockMvc.perform(get("/oauth2/userinfo"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_token"));
        mockMvc.perform(get("/oauth2/userinfo").header("Authorization", "Bearer malformed"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_token"));
    }

    private User confirmedUser(String email) {
        User user = new User(email, "hash", "Test User", true, true, "token");
        user.setEmailConfirmed(true);
        return userRepository.save(user);
    }

    @Test
    void publicClientCodeRefreshAndRevocationWorkWithoutBasicAndConflictingCredentialsFail() throws Exception {
        User user = confirmedUser("public-wire-closure@example.com");
        OAuthClient client = oauthClientRepository.save(new OAuthClient("public-wire-closure", null, true,
                "Public Wire", Set.of("https://client.example/callback"), Set.of("openid", "offline_access"),
                true, Instant.now()));
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        var authz = oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest("code", client.getClientId(),
                "https://client.example/callback", "openid offline_access", "wire-state", pkceChallenge(verifier),
                "S256", "wire-nonce", true));
        var issued = mockMvc.perform(post("/oauth2/token").contentType("application/x-www-form-urlencoded")
                .param("grant_type", "authorization_code").param("client_id", client.getClientId())
                .param("code", codeFrom(authz.redirectUri())).param("redirect_uri", "https://client.example/callback")
                .param("code_verifier", verifier))
                .andExpect(status().isOk()).andExpect(jsonPath("$.refresh_token").isString()).andReturn();
        String refresh = objectMapper.readTree(issued.getResponse().getContentAsString()).get("refresh_token").asText();
        var rotated = mockMvc.perform(post("/oauth2/token").contentType("application/x-www-form-urlencoded")
                .param("grant_type", "refresh_token").param("client_id", client.getClientId()).param("refresh_token", refresh))
                .andExpect(status().isOk()).andReturn();
        String next = objectMapper.readTree(rotated.getResponse().getContentAsString()).get("refresh_token").asText();
        mockMvc.perform(post("/oauth2/revoke").contentType("application/x-www-form-urlencoded")
                .param("client_id", client.getClientId()).param("token", next).param("token_type_hint", "refresh_token"))
                .andExpect(status().isOk());
        mockMvc.perform(post("/oauth2/introspect").contentType("application/x-www-form-urlencoded")
                .param("client_id", client.getClientId()).param("token", next))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));
        mockMvc.perform(post("/oauth2/token").contentType("application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString("other:secret".getBytes(StandardCharsets.UTF_8)))
                .param("grant_type", "refresh_token").param("client_id", client.getClientId()).param("refresh_token", next))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void codeExchangeLifecycleFailuresUseOAuthInvalidGrantWithoutAuthKitEnvelope() throws Exception {
        for (String mutation : List.of("suspended", "unconfirmed", "consent")) {
            User user = confirmedUser("code-owner-" + mutation + "@example.com");
            OAuthClient client = oauthClientRepository.save(new OAuthClient("code-owner-" + mutation, null, true,
                    "Lifecycle", Set.of("https://client.example/callback"), Set.of("openid"), true, Instant.now()));
            String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
            var authz = oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest("code", client.getClientId(),
                    "https://client.example/callback", "openid", "state", pkceChallenge(verifier), "S256", "nonce", true));
            if (mutation.equals("suspended")) user.suspend("test lifecycle", Instant.now());
            if (mutation.equals("unconfirmed")) user.setEmailConfirmed(false);
            if (mutation.equals("consent")) user.recordConsent("old-terms", "old-privacy", "consent", Instant.now());
            userRepository.saveAndFlush(user);
            mockMvc.perform(post("/oauth2/token").contentType("application/x-www-form-urlencoded")
                    .param("grant_type", "authorization_code").param("client_id", client.getClientId())
                    .param("code", codeFrom(authz.redirectUri())).param("redirect_uri", "https://client.example/callback")
                    .param("code_verifier", verifier))
                    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("invalid_grant"))
                    .andExpect(jsonPath("$.error_description").isString())
                    .andExpect(jsonPath("$.data").doesNotExist()).andExpect(jsonPath("$.timestamp").doesNotExist());
        }
    }

    private User confirmedUserWithPassword(String email, String rawPassword) {
        User user = new User(email, passwordEncoder.encode(rawPassword), "Test User", true, true, null);
        user.setEmailConfirmed(true);
        return userRepository.saveAndFlush(user);
    }

    private User platformAdmin(String email, String rawPassword) {
        User admin = new User(email, passwordEncoder.encode(rawPassword), "Admin", true, true, null);
        admin.setEmailConfirmed(true);
        admin.setRole(Role.PLATFORM_ADMIN);
        admin = userRepository.saveAndFlush(admin);
        passkeyCredentialRepository.saveAndFlush(new PasskeyCredential(
                admin.getId(), admin.getTenantId(), "admin-key-" + admin.getId(), "public-key", 0,
                "internal", "Admin key", true, Instant.now()));
        return admin;
    }

    private Jwt freshAdminJwt(User admin) {
        return Jwt.withTokenValue("admin")
                .header("alg", "RS256")
                .subject(admin.getId().toString())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("tenant_id", admin.getTenantId().toString())
                .claim("amr", List.of("pwd", "webauthn"))
                .build();
    }

    private io.github.brenomega.authkit.domain.oauth.dto.OAuthTokenResponse issueOfflineTokens(
            User user, OAuthClient client, String clientSecret, String state) throws Exception {
        String verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        var authz = oauthProviderService.authorize(jwt(user), new OAuthAuthorizeRequest(
                "code", client.getClientId(), "https://client.example/callback", "openid offline_access",
                state, pkceChallenge(verifier), "S256", state + "-nonce", true));
        return oauthProviderService.token("authorization_code", codeFrom(authz.redirectUri()),
                "https://client.example/callback", client.getClientId(), clientSecret, verifier);
    }

    private void assertInactive(io.github.brenomega.authkit.domain.oauth.dto.OAuthTokenResponse tokens,
                                OAuthClient client,
                                String clientSecret) {
        assertEquals(false, oauthProviderService.introspect(
                tokens.accessToken(), "access_token", client.getClientId(), clientSecret).get("active"));
        assertEquals(false, oauthProviderService.introspect(
                tokens.refreshToken(), "refresh_token", client.getClientId(), clientSecret).get("active"));
        assertThrows(InvalidOAuthRequestException.class, () -> oauthProviderService.userInfo(tokens.accessToken()));
    }

    private Jwt jwt(User user) {
        return new Jwt(
                "token",
                Instant.now(),
                Instant.now().plusSeconds(900),
                Map.of("alg", "none"),
                Map.of(
                    "sub",
                    user.getId().toString(),
                    "tenant_id",
                    user.getTenantId().toString(),
                    "amr",
                    List.of("pwd")));
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
