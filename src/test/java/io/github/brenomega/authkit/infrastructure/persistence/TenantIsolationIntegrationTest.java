package io.github.brenomega.authkit.infrastructure.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.ProfileService;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class TenantIsolationIntegrationTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private ProfileService profileService;

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("Service reads are constrained to the JWT tenant_id")
    void serviceRead_withMismatchedTenantClaim_hidesOtherTenantUser() {
        User first = saveUser("tenant-one@example.com");
        User second = saveUser("tenant-two@example.com");
        entityManager.clear();

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(second.getTenantId())));

        assertThrows(UserNotFoundException.class, () -> profileService.getProfile(first.getId().toString()));
    }

    @Test
    @DisplayName("Service reads allow the JWT subject's own tenant")
    void serviceRead_withMatchingTenantClaim_returnsProfile() {
        User user = saveUser("tenant-self@example.com");
        entityManager.clear();

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(user.getTenantId())));

        assertEquals("tenant-self@example.com", profileService.getProfile(user.getId().toString()).email());
    }

    private User saveUser(String email) {
        User user = new User(
                email,
                "hashed-password",
                null,
                null,
                true,
                true,
                UUID.randomUUID().toString());
        user.setEmailConfirmed(true);
        return userRepository.save(user);
    }

    private Jwt jwt(UUID tenantId) {
        Instant now = Instant.now();
        return new Jwt(
                "token",
                now,
                now.plusSeconds(300),
                Map.of("alg", "RS256"),
                Map.of("sub", UUID.randomUUID().toString(), "tenant_id", tenantId.toString()));
    }
}
