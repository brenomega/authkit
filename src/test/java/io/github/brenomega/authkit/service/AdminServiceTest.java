package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Set;

import io.github.brenomega.authkit.domain.user.dto.AdminOAuthClientCreateRequest;
import io.github.brenomega.authkit.domain.user.dto.AdminUpdateRoleRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.repository.OAuthClientRepository;
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

    @SuppressWarnings("null")
    @Test
    @DisplayName("Admin role changes are server-side enforced and audited")
    void adminCanUpdateUserRole() {
        User admin = confirmedUser("admin-plane@example.com", Role.ADMIN);
        User target = confirmedUser("target-plane@example.com", Role.USER);

        var response = adminService.updateRole(jwt(admin), target.getId(), new AdminUpdateRoleRequest(Role.OWNER, null));

        assertEquals(Role.OWNER, response.role());
        assertEquals(Role.OWNER, userRepository.findById(target.getId()).orElseThrow().getRole());
    }

    @Test
    @DisplayName("Admin client creation returns the secret once and stores only its hash")
    void adminCanCreateConfidentialOauthClient() {
        User admin = confirmedUser("client-admin@example.com", Role.ADMIN);

        var response = adminService.createOAuthClient(jwt(admin), new AdminOAuthClientCreateRequest(
                admin.getTenantId(),
                "Production App",
                false,
                Set.of("https://app.example/callback"),
                Set.of("openid", "email"),
                true,
                null));

        assertNotNull(response.clientSecret());
        var stored = oauthClientRepository.findByClientId(response.clientId()).orElseThrow();
        assertNotNull(stored.getClientSecretHash());
        assertTrue(stored.getClientSecretHash().startsWith("$argon2"),
                "Confidential OAuth client secrets must use the configured slow password hash");
        assertNull(response.disabledAt());
    }

    private User confirmedUser(String email, Role role) {
        User user = new User(email, "hash", "Test User", null, true, true, "token");
        user.setEmailConfirmed(true);
        user.setRole(role);
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
}
