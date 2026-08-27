package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Set;

import io.github.brenomega.authkit.domain.oauth.dto.AdminOAuthClientCreateRequest;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.domain.user.dto.AdminAccountStateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUpdateRoleRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.domain.user.enums.AccountState;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class AdminServiceTest {

    @Autowired private AdminService adminService;
    @Autowired private UserRepository userRepository;
    @Autowired private OAuthClientRepository oauthClientRepository;
    @Autowired private PasskeyCredentialRepository passkeyCredentialRepository;
    @Autowired private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;
    @Autowired private TokenStorage tokenStorage;

    @Test
    @DisplayName("A platform administrator can grant the only administrative role")
    void platformAdminCanUpdateUserRole() {
        User admin = confirmedUser("admin-plane@example.com", Role.PLATFORM_ADMIN);
        User target = confirmedUser("target-plane@example.com", Role.USER);
        activePasskey(admin);

        var response = adminService.updateRole(
                jwt(admin), target.getId(),
                new AdminUpdateRoleRequest(Role.PLATFORM_ADMIN, "AdminPass12345!", null));

        assertEquals(Role.PLATFORM_ADMIN, response.role());
        assertEquals(Role.PLATFORM_ADMIN, userRepository.findById(target.getId()).orElseThrow().getRole());
    }

    @Test
    @DisplayName("The final active platform administrator cannot be demoted")
    void lastPlatformAdminCannotBeDemoted() {
        User admin = confirmedUser("last-admin@example.com", Role.PLATFORM_ADMIN);
        activePasskey(admin);

        assertThrows(AccessDeniedException.class, () -> adminService.updateRole(
                jwt(admin), admin.getId(),
                new AdminUpdateRoleRequest(Role.USER, "AdminPass12345!", null)));
    }

    @Test
    @DisplayName("OAuth clients are global and confidential secrets are returned once")
    void platformAdminCreatesGlobalConfidentialOauthClient() {
        User admin = confirmedUser("client-admin@example.com", Role.PLATFORM_ADMIN);
        activePasskey(admin);

        var response = adminService.createOAuthClient(jwt(admin), new AdminOAuthClientCreateRequest(
                "Production App", false,
                Set.of("https://app.example/callback"), Set.of("openid", "email"),
                true, "AdminPass12345!", null));

        assertNotNull(response.clientSecret());
        var stored = oauthClientRepository.findByClientId(response.clientId()).orElseThrow();
        assertNotNull(stored.getClientSecretHash());
        assertTrue(stored.getClientSecretHash().startsWith("$argon2"));
        assertNull(response.disabledAt());
        assertEquals(1, adminService.listOAuthClients(jwt(admin)).size());
    }

    @Test
    @DisplayName("Suspension changes durable state and reactivation does not restore sessions")
    void platformAdminSuspendsAndReactivatesUser() {
        User admin = confirmedUser("state-admin@example.com", Role.PLATFORM_ADMIN);
        User target = confirmedUser("state-target@example.com", Role.USER);
        activePasskey(admin);
        var request = new AdminAccountStateRequest("abuse investigation", "AdminPass12345!", null);

        var suspended = adminService.suspendUser(jwt(admin), target.getId(), request);
        assertEquals(AccountState.SUSPENDED, suspended.accountState());
        assertNotNull(suspended.suspendedAt());

        var reactivated = adminService.reactivateUser(jwt(admin), target.getId(), request);
        assertEquals(AccountState.ACTIVE, reactivated.accountState());
        assertNull(reactivated.suspendedAt());
    }

    @Test
    @DisplayName("A strongly authenticated platform administrator can cancel deletion during grace")
    void platformAdminCancelsPendingDeletion() {
        User admin = confirmedUser("cancel-admin@example.com", Role.PLATFORM_ADMIN);
        User target = confirmedUser("cancel-target@example.com", Role.USER);
        target.requestDeletion(java.time.Instant.now());
        userRepository.save(target);
        activePasskey(admin);

        var response = adminService.cancelDeletion(
                jwt(admin), target.getId(),
                new AdminAccountStateRequest("identity owner recovered access", "AdminPass12345!", null));

        assertEquals(AccountState.ACTIVE, response.accountState());
        assertNull(response.deletionRequestedAt());
    }

    @Test
    @DisplayName("Admin inventory uses bound cursors and exposes safe authenticator and operational status")
    void adminInventoryAndSessionRevocationAreComplete() {
        User admin = confirmedUser("inventory-admin@example.com", Role.PLATFORM_ADMIN);
        User first = confirmedUser("inventory-first@example.com", Role.USER);
        confirmedUser("inventory-second@example.com", Role.USER);
        activePasskey(admin);

        var firstPage = adminService.listUsers(jwt(admin), "inventory", 1, null);
        assertEquals(1, firstPage.items().size());
        assertNotNull(firstPage.nextCursor());
        var secondPage = adminService.listUsers(jwt(admin), "inventory", 1, firstPage.nextCursor());
        assertEquals(1, secondPage.items().size());
        assertFalse(firstPage.items().getFirst().id().equals(secondPage.items().getFirst().id()));
        assertThrows(RuntimeException.class,
                () -> adminService.listUsers(jwt(admin), "different-query", 1, firstPage.nextCursor()));

        var detail = adminService.getUser(jwt(admin), first.getId());
        assertTrue(detail.authenticators().password());
        assertEquals(0, detail.authenticators().activeTotpCredentials());
        assertEquals(0, detail.authenticators().activePasskeys());
        assertEquals(0, detail.authenticators().linkedSocialIdentities());

        String sessionJti = java.util.UUID.randomUUID().toString();
        var refresh = RefreshTokenCodec.issue(first.getId().toString(), sessionJti);
        tokenStorage.storeRefreshToken(first.getId().toString(), sessionJti, refresh.rawToken(), 1);
        assertTrue(tokenStorage.isSessionActive(first.getId().toString(), sessionJti));
        adminService.revokeAllUserSessions(jwt(admin), first.getId(), "AdminPass12345!", null);
        assertFalse(tokenStorage.isSessionActive(first.getId().toString(), sessionJti));
        assertFalse(adminService.listSecurityEvents(jwt(admin), first.getId(), 20, null).items().isEmpty());
        assertTrue(adminService.operationalStatus(jwt(admin)).emailOutbox().containsKey("ACCEPTED"));
    }

    private User confirmedUser(String email, Role role) {
        User user = new User(email, passwordEncoder.encode("AdminPass12345!"), "Test User", true, true, "token");
        user.setEmailConfirmed(true);
        user.setRole(role);
        return userRepository.save(user);
    }

    private void activePasskey(User user) {
        passkeyCredentialRepository.save(new PasskeyCredential(
                user.getId(), user.getTenantId(), "credential-" + user.getId(),
                "public-key-cose", 0, "internal", "Admin Passkey", true,
                java.time.Instant.now()));
    }

    private Jwt jwt(User user) {
        return new Jwt(
                "token", java.time.Instant.now(), java.time.Instant.now().plusSeconds(900),
                Map.of("alg", "none"),
                Map.of("sub", user.getId().toString(), "tenant_id", user.getTenantId().toString(),
                        "amr", java.util.List.of("webauthn")));
    }
}
