package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import io.github.brenomega.authkit.domain.user.dto.AccountDeletionResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

class AccountLifecycleServiceTest {

    private UserRepository userRepository;
    private SecurityEventRepository securityEventRepository;
    private SecurityEventService securityEventService;
    private TokenStorage tokenStorage;
    private PasswordEncoder passwordEncoder;
    private AuthProperties authProperties;
    private AccountLifecycleService service;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        securityEventRepository = mock(SecurityEventRepository.class);
        securityEventService = mock(SecurityEventService.class);
        tokenStorage = mock(TokenStorage.class);
        passwordEncoder = mock(PasswordEncoder.class);
        authProperties = new AuthProperties();
        service = new AccountLifecycleService(
                userRepository,
                securityEventRepository,
                securityEventService,
                tokenStorage,
                passwordEncoder,
                authProperties);
    }

    @Test
    @DisplayName("Account deletion anonymizes PII, revokes sessions, and writes durable events")
    void requestDeletion_anonymizesPiiAndRecordsEvents() {
        UUID userId = UUID.fromString("00000000-0000-0000-0000-000000000111");
        User user = new User("erase@example.com", "old-hash", "Erase Me", "555", true, true, null);
        user.setEmailConfirmed(true);
        ReflectionTestUtils.setField(user, "id", userId);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.encode(any())).thenReturn("deleted-hash");

        AccountDeletionResponse response = service.requestDeletion(userId.toString());

        assertEquals("deleted", response.status());
        assertTrue(user.getEmail().startsWith("deleted+"));
        assertTrue(user.getEmail().endsWith("@deleted.authkit.local"));
        assertEquals("deleted-hash", user.getPassword());
        assertNull(user.getName());
        assertNull(user.getPhone());
        assertNotNull(user.getDeletionRequestedAt());
        assertNotNull(user.getDeletedAt());
        assertNotNull(user.getAnonymizedAt());
        verify(tokenStorage).revokeAllSessions(userId.toString());
        verify(userRepository).save(user);
        verify(securityEventService).record(
                eq(SecurityEventType.ACCOUNT_DELETION_REQUESTED),
                eq(SecurityEventOutcome.SUCCESS),
                eq(SecurityEventSeverity.HIGH),
                eq(userId),
                eq(userId),
                eq(user.getTenantId()),
                eq("erase@example.com"),
                eq("account_deletion_requested"),
                any());
        verify(securityEventService).record(
                eq(SecurityEventType.ACCOUNT_ANONYMIZED),
                eq(SecurityEventOutcome.SUCCESS),
                eq(SecurityEventSeverity.HIGH),
                eq(userId),
                eq(userId),
                eq(user.getTenantId()),
                eq("erase@example.com"),
                eq("account_anonymized"),
                any());
    }

    @Test
    @DisplayName("Data export returns consent and profile data without credential material")
    void exportUserData_returnsGovernanceSnapshot() {
        UUID userId = UUID.fromString("00000000-0000-0000-0000-000000000112");
        User user = new User("export@example.com", "secret-hash", "Export Me", "555", true, true, null);
        user.setEmailConfirmed(true);
        user.recordConsent("terms-2026", "privacy-2026", "consent", Instant.parse("2026-01-01T00:00:00Z"));
        ReflectionTestUtils.setField(user, "id", userId);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(securityEventRepository.findByTargetUserIdOrderByOccurredAtDesc(eq(userId), any())).thenReturn(List.of());

        var response = service.exportUserData(userId.toString());

        assertEquals("export@example.com", response.profile().email());
        assertEquals("terms-2026", response.consent().termsVersion());
        assertEquals("privacy-2026", response.consent().privacyPolicyVersion());
        assertEquals("consent", response.consent().lawfulBasis());
        assertTrue(response.securityEvents().isEmpty());
        verify(securityEventService).recordForUser(
                SecurityEventType.DATA_EXPORT_REQUESTED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "user_data_export_requested");
    }
}
