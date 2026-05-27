package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Set;

import io.github.brenomega.authkit.domain.oauth.entity.OAuthClient;
import io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential;
import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientCreateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientUpdateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUpdateRoleRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.exception.InvalidOAuthRequestException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
import io.github.brenomega.authkit.repository.PasskeyCredentialRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class AdminServiceTest {

    @Autowired
    private AdminService adminService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OAuthClientRepository oauthClientRepository;

    @Autowired
    private PasskeyCredentialRepository passkeyCredentialRepository;

    @Autowired
    private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;

    @SuppressWarnings("null")
    @Test
    @DisplayName("Admin role changes are server-side enforced and audited")
    void adminCanUpdateUserRole() {
        User admin = confirmedUser("admin-plane@example.com", Role.ADMIN);
        User target = confirmedUser("target-plane@example.com", Role.USER);
        activePasskey(admin);

        var response = adminService.updateRole(
                jwt(admin),
                target.getId(),
                new AdminUpdateRoleRequest(Role.OWNER, "AdminPass12345!", null));

        assertEquals(Role.OWNER, response.role());
        assertEquals(Role.OWNER, userRepository.findById(target.getId()).orElseThrow().getRole());
    }

    @Test
    @DisplayName("Admin client creation returns the secret once and stores only its hash")
    void adminCanCreateConfidentialOauthClient() {
        User admin = confirmedUser("client-admin@example.com", Role.ADMIN);
        activePasskey(admin);

        var response = adminService.createOAuthClient(jwt(admin), new AdminOAuthClientCreateRequest(
                admin.getTenantId(),
                "Production App",
                false,
                Set.of("https://app.example/callback"),
                Set.of("openid", "email"),
                true,
                "AdminPass12345!",
                null));

        assertNotNull(response.clientSecret());
        var stored = oauthClientRepository.findByClientId(response.clientId()).orElseThrow();
        assertNotNull(stored.getClientSecretHash());
        assertTrue(stored.getClientSecretHash().startsWith("$argon2"),
                "Confidential OAuth client secrets must use the configured slow password hash");
        assertNull(response.disabledAt());
    }

    @Test
    @DisplayName("Tenant admin reads are scoped to their tenant")
    void tenantAdminListsOnlyOwnTenantUsersAndOauthClients() {
        User tenantAdmin = confirmedUser("tenant-admin-list@example.com", Role.TENANT_ADMIN);
        User otherTenantUser = confirmedUser("tenant-admin-list-other@example.com", Role.USER);
        oauthClientRepository.save(new OAuthClient(
                tenantAdmin.getTenantId(),
                "tenant-owned-client",
                null,
                true,
                "Tenant Owned",
                Set.of("https://tenant.example/callback"),
                Set.of("openid"),
                true,
                java.time.Instant.now()));
        oauthClientRepository.save(new OAuthClient(
                otherTenantUser.getTenantId(),
                "other-owned-client",
                null,
                true,
                "Other Owned",
                Set.of("https://other.example/callback"),
                Set.of("openid"),
                true,
                java.time.Instant.now()));

        var users = adminService.listUsers(jwt(tenantAdmin), 100);
        var clients = adminService.listOAuthClients(jwt(tenantAdmin));

        assertEquals(1, users.size());
        assertEquals(tenantAdmin.getId(), users.getFirst().id());
        assertEquals(1, clients.size());
        assertEquals("tenant-owned-client", clients.getFirst().clientId());
    }

    @Test
    @DisplayName("Tenant admin cannot change roles outside their tenant")
    void tenantAdminCannotUpdateCrossTenantRole() {
        User tenantAdmin = confirmedUser("tenant-admin-role@example.com", Role.TENANT_ADMIN);
        User otherTenantUser = confirmedUser("tenant-admin-role-target@example.com", Role.USER);
        activePasskey(tenantAdmin);

        assertThrows(UserNotFoundException.class, () -> adminService.updateRole(
                jwt(tenantAdmin),
                otherTenantUser.getId(),
                new AdminUpdateRoleRequest(Role.OWNER, "AdminPass12345!", null)));
    }

    @Test
    @DisplayName("Tenant admin cannot create or mutate cross-tenant OAuth clients")
    void tenantAdminCannotManageCrossTenantOauthClients() {
        User tenantAdmin = confirmedUser("tenant-admin-oauth@example.com", Role.TENANT_ADMIN);
        User otherTenantUser = confirmedUser("tenant-admin-oauth-other@example.com", Role.USER);
        activePasskey(tenantAdmin);
        OAuthClient otherClient = oauthClientRepository.save(new OAuthClient(
                otherTenantUser.getTenantId(),
                "other-tenant-client",
                null,
                true,
                "Other Tenant",
                Set.of("https://other-client.example/callback"),
                Set.of("openid"),
                true,
                java.time.Instant.now()));

        assertThrows(InvalidOAuthRequestException.class, () -> adminService.createOAuthClient(
                jwt(tenantAdmin),
                new AdminOAuthClientCreateRequest(
                        otherTenantUser.getTenantId(),
                        "Cross Tenant",
                        true,
                        Set.of("https://cross.example/callback"),
                        Set.of("openid"),
                        true,
                        "AdminPass12345!",
                        null)));

        assertThrows(InvalidOAuthRequestException.class, () -> adminService.updateOAuthClient(
                jwt(tenantAdmin),
                otherClient.getId(),
                new AdminOAuthClientUpdateRequest(
                        "Mutated",
                        Set.of("https://mutated.example/callback"),
                        Set.of("openid"),
                        true,
                        "AdminPass12345!",
                        null)));

        assertThrows(InvalidOAuthRequestException.class, () -> adminService.disableOAuthClient(
                jwt(tenantAdmin),
                otherClient.getId(),
                "AdminPass12345!",
                null));
    }

    private User confirmedUser(String email, Role role) {
        User user = new User(email, passwordEncoder.encode("AdminPass12345!"), "Test User", null, true, true, "token");
        user.setEmailConfirmed(true);
        user.setRole(role);
        return userRepository.save(user);
    }

    private void activePasskey(User user) {
        passkeyCredentialRepository.save(new PasskeyCredential(
                user.getId(),
                user.getTenantId(),
                "credential-" + user.getId(),
                "public-key-cose",
                0,
                "internal",
                "Admin Passkey",
                true,
                java.time.Instant.now()));
    }

    private Jwt jwt(User user) {
        return new Jwt(
                "token",
                java.time.Instant.now(),
                java.time.Instant.now().plusSeconds(900),
                Map.of("alg", "none"),
                Map.of("sub", user.getId().toString(), "tenant_id", user.getTenantId().toString(), "amr", java.util.List.of("webauthn")));
    }
}
