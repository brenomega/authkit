package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import io.github.brenomega.authkit.domain.social.dto.SocialLoginStartRequest;
import io.github.brenomega.authkit.domain.social.dto.AdminSocialProviderCreateRequest;
import io.github.brenomega.authkit.domain.social.entity.OidcClientAuthMethod;
import io.github.brenomega.authkit.domain.social.entity.SocialIdentityProvider;
import io.github.brenomega.authkit.domain.social.entity.SocialProviderType;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.exception.InvalidSocialLoginException;
import io.github.brenomega.authkit.exception.SocialLinkRequiredException;
import io.github.brenomega.authkit.infrastructure.security.SocialSecretCipher;
import io.github.brenomega.authkit.repository.SocialIdentityProviderRepository;
import io.github.brenomega.authkit.repository.SocialIdentityRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.SocialOidcClient;

@SpringBootTest
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "authkit.auth.social.enabled=true",
        "authkit.auth.social.issuer-allowlist=https://issuer.example",
        "authkit.auth.social.callback-base-url=https://auth.example"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class SocialIdentityServiceIntegrationTest {
    @Autowired SocialIdentityService service;
    @Autowired SocialIdentityProviderRepository providers;
    @Autowired SocialIdentityRepository identities;
    @Autowired UserRepository users;
    @Autowired SocialSecretCipher cipher;
    @Autowired PasswordEncoder passwords;
    @Autowired SocialProviderAdminService providerAdminService;
    @Autowired io.github.brenomega.authkit.repository.PasskeyCredentialRepository passkeyRepository;
    @MockitoBean SocialOidcClient oidc;

    @BeforeEach
    void metadata() {
        when(oidc.metadata(any())).thenReturn(new SocialOidcClient.OidcProviderMetadata(
                "https://issuer.example", "https://issuer.example/authorize",
                "https://issuer.example/token", "https://issuer.example/jwks"));
    }

    @Test
    void createsSocialOnlyAccountWithImmutableIdentityAndRejectsStateReplay() {
        SocialIdentityProvider provider = provider("generic-create");
        var start = service.startLogin(provider.getProviderKey(), new SocialLoginStartRequest(true, true));
        String state = query(start.authorizationUrl(), "state");
        assertEquals("S256", query(start.authorizationUrl(), "code_challenge_method"));
        assertFalse(query(start.authorizationUrl(), "code_challenge").isBlank());
        assertFalse(query(start.authorizationUrl(), "nonce").isBlank());

        when(oidc.exchangeAndVerify(any(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(claim("social-new@example.com", "subject-new"));

        var result = service.callback(provider.getProviderKey(), state, "provider-code");
        assertEquals("authenticated", result.response().status());
        assertTrue(result.response().login().accessToken().split("\\.").length == 3);
        assertFalse(result.refreshToken().isBlank());
        User user = users.findByEmail("social-new@example.com").orElseThrow();
        assertNull(user.getPassword());
        assertTrue(user.isEmailConfirmed());
        assertEquals(user.getId(), identities.findByIssuerAndSubject("https://issuer.example", "subject-new")
                .orElseThrow().getUserId());
        assertThrows(InvalidSocialLoginException.class,
                () -> service.callback(provider.getProviderKey(), state, "provider-code"));
    }

    @Test
    void matchingEmailNeverAutoLinks() {
        SocialIdentityProvider provider = provider("generic-no-autolink");
        User local = new User("local-existing@example.com", passwords.encode("Password123!"), null, true, true, null);
        local.setEmailConfirmed(true);
        users.saveAndFlush(local);
        String state = query(service.startLogin(provider.getProviderKey(),
                new SocialLoginStartRequest(true, true)).authorizationUrl(), "state");
        when(oidc.exchangeAndVerify(any(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(claim("local-existing@example.com", "subject-collision"));

        assertThrows(SocialLinkRequiredException.class,
                () -> service.callback(provider.getProviderKey(), state, "provider-code"));
        assertTrue(identities.findByIssuerAndSubject("https://issuer.example", "subject-collision").isEmpty());
    }

    @Test
    void authenticatedAccountCanExplicitlyLinkMatchingProviderIdentity() {
        SocialIdentityProvider provider = provider("generic-explicit-link");
        User local = new User("explicit-link@example.com", passwords.encode("Password123!"), null, true, true, null);
        local.setEmailConfirmed(true);
        local = users.saveAndFlush(local);
        Jwt jwt = jwt(local);
        String state = query(service.startLink(provider.getProviderKey(), jwt,
                new StepUpRequest("Password123!")).authorizationUrl(), "state");
        when(oidc.exchangeAndVerify(any(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(claim("explicit-link@example.com", "subject-explicit"));

        var result = service.callback(provider.getProviderKey(), state, "provider-code");
        assertEquals("linked", result.response().status());
        assertNull(result.refreshToken());
        assertEquals(local.getId(), identities.findByIssuerAndSubject(
                "https://issuer.example", "subject-explicit").orElseThrow().getUserId());
    }

    @Test
    void platformAdminCanConfigureAllowlistedProviderWithoutSecretDisclosure() {
        User admin = new User("provider-admin@example.com", passwords.encode("Password123!"), null, true, true, null);
        admin.setEmailConfirmed(true);
        admin.setRole(Role.PLATFORM_ADMIN);
        admin = users.saveAndFlush(admin);
        passkeyRepository.saveAndFlush(new PasskeyCredential(admin.getId(), admin.getTenantId(),
                "admin-passkey-" + admin.getId(), "public-key", 0, "internal", "Admin key", true, Instant.now()));
        Jwt jwt = Jwt.withTokenValue("test").header("alg", "RS256").subject(admin.getId().toString())
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(300))
                .claim("tenant_id", admin.getTenantId().toString()).claim("amr", List.of("pwd", "webauthn"))
                .build();

        var response = providerAdminService.create(jwt, new AdminSocialProviderCreateRequest(
                "google", "Google", SocialProviderType.GENERIC_OIDC, "https://issuer.example",
                "google-client", "provider-secret-value", Set.of("openid", "email", "profile"),
                OidcClientAuthMethod.CLIENT_SECRET_BASIC, "Password123!", null));

        assertEquals("google", response.providerKey());
        SocialIdentityProvider stored = providers.findByProviderKey("google").orElseThrow();
        assertFalse(stored.getEncryptedClientSecret().contains("provider-secret-value"));
        assertEquals("provider-secret-value", cipher.decrypt(stored.getEncryptedClientSecret()));
    }

    @Test
    void oneTimeStateHasExactlyOneConcurrentWinner() throws Exception {
        SocialIdentityProvider provider = provider("generic-race");
        String state = query(service.startLogin(provider.getProviderKey(),
                new SocialLoginStartRequest(true, true)).authorizationUrl(), "state");
        when(oidc.exchangeAndVerify(any(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(claim("social-race@example.com", "subject-race"));
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        try (var executor = Executors.newFixedThreadPool(2)) {
            for (int i = 0; i < 2; i++) {
                executor.submit(() -> {
                    ready.countDown();
                    try {
                        start.await(5, TimeUnit.SECONDS);
                        service.callback(provider.getProviderKey(), state, "provider-code");
                        success.incrementAndGet();
                    } catch (InvalidSocialLoginException ex) {
                        rejected.incrementAndGet();
                    } catch (Exception ex) {
                        throw new RuntimeException(ex);
                    }
                });
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            executor.shutdown();
            assertTrue(executor.awaitTermination(15, TimeUnit.SECONDS));
        }
        assertEquals(1, success.get());
        assertEquals(1, rejected.get());
        assertEquals(1, identities.findByUserIdOrderByCreatedAtDesc(
                users.findByEmail("social-race@example.com").orElseThrow().getId()).size());
    }

    private SocialIdentityProvider provider(String key) {
        return providers.saveAndFlush(new SocialIdentityProvider(key, "Generic", SocialProviderType.GENERIC_OIDC,
                "https://issuer.example", "client-" + key, cipher.encrypt("client-secret"),
                Set.of("openid", "email", "profile"), OidcClientAuthMethod.CLIENT_SECRET_BASIC, Instant.now()));
    }

    private SocialOidcClient.FederatedIdentity claim(String email, String subject) {
        return new SocialOidcClient.FederatedIdentity("https://issuer.example", subject, email, true,
                "Social User", null, List.of());
    }

    private Jwt jwt(User user) {
        return Jwt.withTokenValue("test")
                .header("alg", "RS256")
                .subject(user.getId().toString())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(300))
                .claim("tenant_id", user.getTenantId().toString())
                .claim("amr", List.of("pwd"))
                .build();
    }

    private String query(String url, String name) {
        return Arrays.stream(URI.create(url).getRawQuery().split("&"))
                .map(part -> part.split("=", 2))
                .filter(parts -> URLDecoder.decode(parts[0], StandardCharsets.UTF_8).equals(name))
                .map(parts -> parts.length == 2 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "")
                .findFirst().orElseThrow();
    }
}
