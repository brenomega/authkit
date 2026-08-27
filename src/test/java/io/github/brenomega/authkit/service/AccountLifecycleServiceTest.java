package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.util.ReflectionTestUtils;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.github.brenomega.authkit.domain.user.dto.AccountDeletionResponse;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.enums.AccountState;
import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventRepository;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.UserAuthoritiesFilter;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.repository.OAuthConsentRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

class AccountLifecycleServiceTest {

    private UserRepository userRepository;
    private SecurityEventRepository securityEventRepository;
    private ConsentEventRepository consentEventRepository;
    private OAuthConsentRepository oauthConsentRepository;
    private SecurityEventService securityEventService;
    private TokenStorage tokenStorage;
    private PasswordEncoder passwordEncoder;
    private AuthProperties authProperties;
    private UserAuthoritiesFilter userAuthoritiesFilter;
    private MfaService mfaService;
    private AccountLockoutService lockoutService;
    private EmailOutboxService emailOutboxService;
    private AbuseThrottleService abuseThrottleService;
    private io.github.brenomega.authkit.repository.SocialIdentityRepository socialIdentityRepository;
    private io.github.brenomega.authkit.repository.SocialIdentityProviderRepository socialIdentityProviderRepository;
    private io.github.brenomega.authkit.repository.PasskeyCredentialRepository passkeyCredentialRepository;
    private io.github.brenomega.authkit.repository.MfaTotpCredentialRepository mfaTotpCredentialRepository;
    private io.github.brenomega.authkit.repository.PasswordHistoryRepository passwordHistoryRepository;
    private AccountLifecycleService service;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        securityEventRepository = mock(SecurityEventRepository.class);
        consentEventRepository = mock(ConsentEventRepository.class);
        oauthConsentRepository = mock(OAuthConsentRepository.class);
        securityEventService = mock(SecurityEventService.class);
        tokenStorage = mock(TokenStorage.class);
        passwordEncoder = mock(PasswordEncoder.class);
        userAuthoritiesFilter = mock(UserAuthoritiesFilter.class);
        mfaService = mock(MfaService.class);
        lockoutService = mock(AccountLockoutService.class);
        emailOutboxService = mock(EmailOutboxService.class);
        abuseThrottleService = mock(AbuseThrottleService.class);
        authProperties = new AuthProperties();
        var argon2Limiter = new Argon2ConcurrencyLimiter();
        socialIdentityRepository = mock(io.github.brenomega.authkit.repository.SocialIdentityRepository.class);
        var socialTransactions = mock(io.github.brenomega.authkit.repository.SocialLoginTransactionRepository.class);
        socialIdentityProviderRepository = mock(io.github.brenomega.authkit.repository.SocialIdentityProviderRepository.class);
        passkeyCredentialRepository = mock(io.github.brenomega.authkit.repository.PasskeyCredentialRepository.class);
        mfaTotpCredentialRepository = mock(io.github.brenomega.authkit.repository.MfaTotpCredentialRepository.class);
        passwordHistoryRepository = mock(io.github.brenomega.authkit.repository.PasswordHistoryRepository.class);
        when(tokenStorage.listSessions(any(), eq(100), any())).thenReturn(
                new io.github.brenomega.authkit.service.spi.SessionPage(List.of(), null));
        service = new AccountLifecycleService(
                userRepository,
                securityEventRepository,
                consentEventRepository,
                oauthConsentRepository,
                securityEventService,
                tokenStorage,
                authProperties,
                userAuthoritiesFilter,
                mfaService,
                new StepUpService(passwordEncoder, argon2Limiter, lockoutService, securityEventService, abuseThrottleService),
                emailOutboxService,
                abuseThrottleService,
                socialIdentityRepository,
                socialTransactions,
                socialIdentityProviderRepository,
                passkeyCredentialRepository,
                mfaTotpCredentialRepository,
                passwordHistoryRepository);
    }

    @SuppressWarnings("null")
@Test
    @DisplayName("Account deletion enters grace, preserves PII temporarily, revokes sessions, and audits")
    void requestDeletion_entersGraceAndRevokesSessions() {
        UUID userId = UUID.fromString("00000000-0000-0000-0000-000000000111");
        User user = new User("erase@example.com", "old-hash", "Erase Me", true, true, null);
        user.setEmailConfirmed(true);
        ReflectionTestUtils.setField(user, "id", userId);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("current-pass", "old-hash")).thenReturn(true);

        AccountDeletionResponse response = service.requestDeletion(userId.toString(), new StepUpRequest("current-pass"));

        assertEquals("deletion_pending", response.status());
        assertEquals("erase@example.com", user.getEmail());
        assertEquals("old-hash", user.getPassword());
        assertEquals("Erase Me", user.getName());
        assertNotNull(user.getDeletionRequestedAt());
        assertNotNull(response.graceExpiresAt());
        assertNull(user.getDeletedAt());
        assertNull(user.getAnonymizedAt());
        verify(userAuthoritiesFilter).evict(userId);
        verify(tokenStorage).revokeAllSessions(userId.toString());
        verify(userRepository).save(user);
        verify(mfaService).requireMfaIfEnabled(user, null, "account_deletion");
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
        verify(securityEventService, never()).record(
                eq(SecurityEventType.ACCOUNT_ANONYMIZED), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Account deletion cannot remove the last active platform administrator")
    void requestDeletion_lastPlatformAdminIsRejected() {
        UUID userId = UUID.fromString("00000000-0000-0000-0000-000000000114");
        User user = new User("last-admin@example.com", "old-hash", "Last Admin", true, true, null);
        user.setEmailConfirmed(true);
        user.setRole(Role.PLATFORM_ADMIN);
        ReflectionTestUtils.setField(user, "id", userId);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(userRepository.countByRoleAndAccountState(Role.PLATFORM_ADMIN, AccountState.ACTIVE)).thenReturn(1L);
        when(passwordEncoder.matches("current-pass", "old-hash")).thenReturn(true);

        assertThrows(AccessDeniedException.class,
                () -> service.requestDeletion(userId.toString(), new StepUpRequest("current-pass")));

        assertTrue(user.isActive());
        verify(userRepository, never()).save(any());
        verify(tokenStorage, never()).revokeAllSessions(any());
        verify(securityEventService, never()).record(
                eq(SecurityEventType.ACCOUNT_DELETION_REQUESTED), any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("A configured zero-day grace anonymizes immediately and irreversibly")
    void requestDeletion_zeroDayGraceAnonymizesImmediately() {
        UUID userId = UUID.fromString("00000000-0000-0000-0000-000000000115");
        User user = new User("zero-grace@example.com", "old-hash", "Erase Now", true, true, null);
        user.setEmailConfirmed(true);
        ReflectionTestUtils.setField(user, "id", userId);
        authProperties.getCompliance().setDeletionGracePeriodDays(0);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("current-pass", "old-hash")).thenReturn(true);

        AccountDeletionResponse response = service.requestDeletion(
                userId.toString(), new StepUpRequest("current-pass"));

        assertEquals("anonymized", response.status());
        assertEquals(AccountState.ANONYMIZED, user.getAccountState());
        assertNull(user.getPassword());
        assertNull(user.getName());
        assertNotNull(user.getAnonymizedAt());
        verify(emailOutboxService).deleteByRecipients(List.of("zero-grace@example.com"));
        verify(securityEventService).record(
                eq(SecurityEventType.ACCOUNT_ANONYMIZED), eq(SecurityEventOutcome.SUCCESS),
                eq(SecurityEventSeverity.HIGH), eq(userId), eq(userId), eq(user.getTenantId()),
                eq("zero-grace@example.com"), eq("account_anonymized"), any());
    }

    @SuppressWarnings("null")
@Test
    @DisplayName("Data export returns consent and profile data without credential material")
    void exportUserData_returnsGovernanceSnapshot() {
        UUID userId = UUID.fromString("00000000-0000-0000-0000-000000000112");
        User user = new User("export@example.com", "secret-hash", "Export Me", true, true, null);
        user.setEmailConfirmed(true);
        user.recordConsent("terms-2026", "privacy-2026", "consent", Instant.parse("2026-01-01T00:00:00Z"));
        ReflectionTestUtils.setField(user, "id", userId);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("current-pass", "secret-hash")).thenReturn(true);
        var securityEvent = mock(io.github.brenomega.authkit.infrastructure.audit.SecurityEvent.class);
        when(securityEvent.getOccurredAt()).thenReturn(Instant.parse("2026-02-01T00:00:00Z"));
        when(securityEvent.getEventType()).thenReturn(SecurityEventType.LOGIN_SUCCESS);
        when(securityEvent.getOutcome()).thenReturn(SecurityEventOutcome.SUCCESS);
        when(securityEvent.getSeverity()).thenReturn(SecurityEventSeverity.LOW);
        when(securityEvent.getEmailMasked()).thenReturn("e***@example.com");
        when(securityEvent.getClientIpMasked()).thenReturn("192.0.2.0/24");
        when(securityEvent.getReason()).thenReturn("login_success");
        when(securityEvent.getMetadataJson()).thenReturn("{\"internalSecret\":\"must-not-export\"}");

        var consentEvent = mock(io.github.brenomega.authkit.infrastructure.audit.ConsentEvent.class);
        when(consentEvent.getTermsVersion()).thenReturn("terms-2025");
        when(consentEvent.getPrivacyPolicyVersion()).thenReturn("privacy-2025");
        when(consentEvent.getLawfulBasis()).thenReturn("consent");
        when(consentEvent.getAcceptedAt()).thenReturn(Instant.parse("2025-01-01T00:00:00Z"));
        when(consentEvent.getRecordedAt()).thenReturn(Instant.parse("2025-01-01T00:00:01Z"));
        when(consentEvent.getEventHash()).thenReturn("audit-integrity-hash");

        var oauthConsent = new io.github.brenomega.authkit.domain.oauth.entity.OAuthConsent(
                userId, user.getTenantId(), "client-public-id", java.util.Set.of("openid", "profile"),
                Instant.parse("2026-02-02T00:00:00Z"));
        var passwordHistory = new io.github.brenomega.authkit.domain.user.entity.PasswordHistoryEntry(
                userId, "historical-secret-hash", Instant.parse("2025-06-01T00:00:00Z"));

        var totp = mock(io.github.brenomega.authkit.domain.mfa.entity.MfaTotpCredential.class);
        when(totp.getId()).thenReturn(UUID.fromString("00000000-0000-0000-0000-000000000212"));
        when(totp.getEncryptedSecret()).thenReturn("encrypted-totp-secret-must-not-export");
        when(totp.getCreatedAt()).thenReturn(Instant.parse("2026-02-03T00:00:00Z"));

        var passkey = mock(io.github.brenomega.authkit.domain.passkey.entity.PasskeyCredential.class);
        when(passkey.getId()).thenReturn(UUID.fromString("00000000-0000-0000-0000-000000000213"));
        when(passkey.getCredentialId()).thenReturn("credential-id-must-not-export");
        when(passkey.getPublicKeyCose()).thenReturn("public-key-must-not-export");
        when(passkey.getLabel()).thenReturn("Laptop");
        when(passkey.getSignatureCount()).thenReturn(7L);
        when(passkey.getCreatedAt()).thenReturn(Instant.parse("2026-02-04T00:00:00Z"));

        UUID providerId = UUID.fromString("00000000-0000-0000-0000-000000000214");
        var social = mock(io.github.brenomega.authkit.domain.social.entity.SocialIdentity.class);
        when(social.getId()).thenReturn(UUID.fromString("00000000-0000-0000-0000-000000000215"));
        when(social.getProviderId()).thenReturn(providerId);
        when(social.getIssuer()).thenReturn("https://issuer.example");
        when(social.getSubject()).thenReturn("provider-subject-must-not-export");
        when(social.getCreatedAt()).thenReturn(Instant.parse("2026-02-05T00:00:00Z"));
        var provider = mock(io.github.brenomega.authkit.domain.social.entity.SocialIdentityProvider.class);
        when(provider.getProviderKey()).thenReturn("example-oidc");
        when(provider.getEncryptedClientSecret()).thenReturn("provider-client-secret-must-not-export");

        when(securityEventRepository.findByTargetUserIdOrderByOccurredAtDesc(userId)).thenReturn(List.of(securityEvent));
        when(consentEventRepository.findByUserIdOrderByAcceptedAtDesc(userId)).thenReturn(List.of(consentEvent));
        when(oauthConsentRepository.findByUserIdOrderByGrantedAtDesc(userId)).thenReturn(List.of(oauthConsent));
        when(passwordHistoryRepository.findByUserIdOrderByCreatedAtDesc(userId)).thenReturn(List.of(passwordHistory));
        when(mfaTotpCredentialRepository.findByUserIdOrderByCreatedAtDesc(userId)).thenReturn(List.of(totp));
        when(passkeyCredentialRepository.findByUserIdOrderByCreatedAtDesc(userId)).thenReturn(List.of(passkey));
        when(socialIdentityRepository.findByUserIdOrderByCreatedAtDesc(userId)).thenReturn(List.of(social));
        when(socialIdentityProviderRepository.findById(providerId)).thenReturn(Optional.of(provider));
        when(tokenStorage.listSessions(userId.toString(), 100, null)).thenReturn(
                new io.github.brenomega.authkit.service.spi.SessionPage(List.of(
                        new io.github.brenomega.authkit.service.spi.SessionMetadata(
                                "00000000-0000-0000-0000-000000000216", "jwt-jti-must-not-export",
                                Instant.parse("2026-02-06T00:00:00Z"), Instant.parse("2026-02-06T00:01:00Z"),
                                Instant.parse("2026-02-13T00:00:00Z"), List.of("pwd"), "Firefox", "Laptop",
                                "192.0.2.0/24", "192.0.2.0/24")), null));

        var response = service.exportUserData(userId.toString(), new StepUpRequest("current-pass"));

        assertEquals("export@example.com", response.profile().email());
        assertEquals("terms-2026", response.consent().termsVersion());
        assertEquals("privacy-2026", response.consent().privacyPolicyVersion());
        assertEquals("consent", response.consent().lawfulBasis());
        assertEquals("authkit-user-data-export/v1", response.schemaVersion());
        assertTrue(response.credentials().localPasswordConfigured());
        assertEquals(1, response.sessions().size());
        assertEquals(1, response.consentHistory().size());
        assertEquals(1, response.oauthConsents().size());
        assertEquals(1, response.securityEvents().size());
        assertEquals(1, response.credentials().passwordHistory().size());
        assertEquals(1, response.credentials().totp().size());
        assertEquals(1, response.credentials().passkeys().size());
        assertEquals(1, response.credentials().socialIdentities().size());
        try {
            String json = new com.fasterxml.jackson.databind.ObjectMapper().findAndRegisterModules()
                    .writeValueAsString(response);
            assertFalse(json.contains("secret-hash"));
            assertFalse(json.contains("historical-secret-hash"));
            assertFalse(json.contains("encrypted-totp-secret-must-not-export"));
            assertFalse(json.contains("credential-id-must-not-export"));
            assertFalse(json.contains("public-key-must-not-export"));
            assertFalse(json.contains("provider-subject-must-not-export"));
            assertFalse(json.contains("provider-client-secret-must-not-export"));
            assertFalse(json.contains("jwt-jti-must-not-export"));
            assertFalse(json.contains("must-not-export"));
        } catch (com.fasterxml.jackson.core.JsonProcessingException exception) {
            throw new AssertionError(exception);
        }
        verify(securityEventService).recordForAuthenticatedUser(
                SecurityEventType.DATA_EXPORT_REQUESTED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "user_data_export_requested");
        verify(mfaService).requireMfaIfEnabled(user, null, "data_export");
    }

    @SuppressWarnings("null")
@Test
    @DisplayName("Data export requires a fresh password step-up")
    void exportUserData_invalidStepUp_deniesExport() {
        UUID userId = UUID.fromString("00000000-0000-0000-0000-000000000113");
        User user = new User("step-up@example.com", "secret-hash", "Step Up", true, true, null);
        user.setEmailConfirmed(true);
        ReflectionTestUtils.setField(user, "id", userId);

        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-pass", "secret-hash")).thenReturn(false);

        assertThrows(InvalidCredentialsException.class,
                () -> service.exportUserData(userId.toString(), new StepUpRequest("wrong-pass")));

        verify(securityEventRepository, never()).findByTargetUserIdOrderByOccurredAtDesc(any());
        verify(consentEventRepository, never()).findByUserIdOrderByAcceptedAtDesc(any());
        verify(oauthConsentRepository, never()).findByUserIdOrderByGrantedAtDesc(any());
        verify(mfaService, never()).requireMfaIfEnabled(any(), any(), any());
        verify(securityEventService).recordForAuthenticatedUser(
                SecurityEventType.DATA_EXPORT_REQUESTED,
                SecurityEventOutcome.DENIED,
                SecurityEventSeverity.HIGH,
                user,
                "data_export_step_up_failed");
    }
}
