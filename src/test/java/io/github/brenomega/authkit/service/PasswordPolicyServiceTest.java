package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import io.github.brenomega.authkit.domain.user.entity.PasswordHistoryEntry;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.WeakPasswordException;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.repository.PasswordHistoryRepository;

class PasswordPolicyServiceTest {

    private PasswordHistoryRepository passwordHistoryRepository;
    private PasswordEncoder passwordEncoder;
    private PasswordPolicyService passwordPolicyService;

    @BeforeEach
    void setUp() {
        passwordHistoryRepository = mock(PasswordHistoryRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        passwordPolicyService = new PasswordPolicyService(
                passwordHistoryRepository,
                passwordEncoder,
                new Argon2ConcurrencyLimiter());
    }

    @Test
    @DisplayName("Rejects common, identity-derived, and recent password reuse")
    void validateForUser_rejectsWeakAndReusedPasswords() {
        User user = new User("person@example.com", "current-hash", "Person Example", null, true, true, null);
        ReflectionTestUtils.setField(user, "id", java.util.UUID.randomUUID());

        assertThrows(WeakPasswordException.class,
                () -> passwordPolicyService.validateForRegistration("user@example.com", "password123"));
        assertThrows(WeakPasswordException.class,
                () -> passwordPolicyService.validateForRegistration("person@example.com", "Person!2345"));

        PasswordHistoryEntry historyEntry = new PasswordHistoryEntry(
                user.getId(),
                "old-hash",
                java.time.Instant.now());
        when(passwordHistoryRepository.findByUserIdOrderByCreatedAtDesc(
                org.mockito.Mockito.eq(user.getId()),
                org.mockito.Mockito.any(Pageable.class)))
                .thenReturn(List.of(historyEntry));
        when(passwordEncoder.matches("BetterPass123!", "current-hash")).thenReturn(false);
        when(passwordEncoder.matches("BetterPass123!", "old-hash")).thenReturn(true);

        assertThrows(WeakPasswordException.class,
                () -> passwordPolicyService.validateForUser(user, "BetterPass123!"));
    }

    @Test
    @DisplayName("Accepts sufficiently complex non-reused passwords")
    void validateForRegistration_acceptsStrongPassword() {
        assertDoesNotThrow(() ->
                passwordPolicyService.validateForRegistration("user@example.com", "UsefulVault47!"));
    }
}
