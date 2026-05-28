package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.util.ReflectionTestUtils;

import io.github.brenomega.authkit.domain.mfa.entity.MfaBackupCode;
import io.github.brenomega.authkit.domain.mfa.entity.MfaTotpCredential;
import io.github.brenomega.authkit.domain.mfa.util.Base32;
import io.github.brenomega.authkit.domain.mfa.util.TotpGenerator;
import io.github.brenomega.authkit.domain.user.dto.MfaTotpConfirmRequest;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.exception.InvalidMfaCodeException;
import io.github.brenomega.authkit.exception.MfaRequiredException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.AuditDigestService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;
import io.github.brenomega.authkit.infrastructure.security.MfaSecretCipher;
import io.github.brenomega.authkit.infrastructure.security.MfaStatusCache;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.github.brenomega.authkit.repository.MfaBackupCodeRepository;
import io.github.brenomega.authkit.repository.MfaTotpCredentialRepository;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

class MfaServiceTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000201");
    private static final UUID TENANT_ID = UUID.fromString("00000000-0000-0000-0000-000000000202");

    private UserRepository userRepository;
    private MfaTotpCredentialRepository totpRepository;
    private MfaBackupCodeRepository backupCodeRepository;
    private PasswordEncoder passwordEncoder;
    private SecurityEventService securityEventService;
    private AccountLockoutService lockoutService;
    private TokenStorage tokenStorage;
    private AuthProperties authProperties;
    private AuditDigestService auditDigestService;
    private MfaSecretCipher mfaSecretCipher;
    private AbuseThrottleService abuseThrottleService;
    private MfaService service;
    private User user;

    @SuppressWarnings("null")
    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        totpRepository = mock(MfaTotpCredentialRepository.class);
        backupCodeRepository = mock(MfaBackupCodeRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        securityEventService = mock(SecurityEventService.class);
        lockoutService = mock(AccountLockoutService.class);
        tokenStorage = mock(TokenStorage.class);
        authProperties = new AuthProperties();
        authProperties.getMfa().setSecretEncryptionKdfIterations(1000);
        auditDigestService = new AuditDigestService(authProperties);
        mfaSecretCipher = new MfaSecretCipher(authProperties);
        abuseThrottleService = mock(AbuseThrottleService.class);
        service = new MfaService(
                userRepository,
                totpRepository,
                backupCodeRepository,
                mfaSecretCipher,
                authProperties,
                securityEventService,
                auditDigestService,
                tokenStorage,
                new MfaStatusCache(authProperties, new SimpleMeterRegistry()),
                new StepUpService(
                        passwordEncoder,
                        new Argon2ConcurrencyLimiter(),
                        lockoutService,
                        securityEventService,
                        abuseThrottleService),
                abuseThrottleService);

        user = new User("mfa@example.com", "hashed-pass", "Mfa User", "555", true, true, null);
        user.setEmailConfirmed(true);
        ReflectionTestUtils.setField(user, "id", USER_ID);
        ReflectionTestUtils.setField(user, "tenantId", TENANT_ID);
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
        when(lockoutService.isLocked("mfa@example.com")).thenReturn(false);
        when(passwordEncoder.matches("current-pass", "hashed-pass")).thenReturn(true);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("TOTP enrollment replaces stale pending credentials and stores encrypted secret")
    void startTotpEnrollment_replacesPendingAndStoresEncryptedSecret() {
        UUID credentialId = UUID.fromString("00000000-0000-0000-0000-000000000203");
        when(totpRepository.save(any(MfaTotpCredential.class))).thenAnswer(invocation -> {
            MfaTotpCredential credential = invocation.getArgument(0);
            ReflectionTestUtils.setField(credential, "id", credentialId);
            return credential;
        });

        var response = service.startTotpEnrollment(USER_ID.toString(), new StepUpRequest("current-pass"));

        assertEquals(credentialId, response.credentialId());
        assertNotNull(response.secret());
        assertTrue(response.otpauthUri().startsWith("otpauth://totp/AuthKit%3Amfa%40example.com"));
        verify(totpRepository).deleteByUserIdAndConfirmedFalse(USER_ID);

        ArgumentCaptor<MfaTotpCredential> credentialCaptor = ArgumentCaptor.forClass(MfaTotpCredential.class);
        verify(totpRepository).save(credentialCaptor.capture());
        assertNotEquals(response.secret(), credentialCaptor.getValue().getEncryptedSecret());
        assertEquals(response.secret(), mfaSecretCipher.decrypt(credentialCaptor.getValue().getEncryptedSecret()));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("TOTP confirmation enables MFA, generates hashed backup codes, and revokes sessions")
    void confirmTotp_generatesBackupCodesAndRevokesSessions() {
        UUID credentialId = UUID.fromString("00000000-0000-0000-0000-000000000204");
        String secret = Base32.encode("12345678901234567890".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        MfaTotpCredential credential = new MfaTotpCredential(
                USER_ID, TENANT_ID, mfaSecretCipher.encrypt(secret), Instant.now());
        ReflectionTestUtils.setField(credential, "id", credentialId);
        String code = new TotpGenerator().currentCode(secret);

        when(totpRepository.findByIdAndUserId(credentialId, USER_ID)).thenReturn(Optional.of(credential));
        when(backupCodeRepository.saveAll(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var response = service.confirmTotp(
                USER_ID.toString(),
                new MfaTotpConfirmRequest(credentialId, "current-pass", code));

        assertTrue(credential.isConfirmed());
        assertNotNull(credential.getConfirmedAt());
        assertNotNull(credential.getLastUsedTimeStep());
        assertEquals(authProperties.getMfa().getBackupCodeCount(), response.backupCodes().size());
        response.backupCodes().forEach(rawCode -> assertTrue(rawCode.matches("[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}")));
        verify(backupCodeRepository).deleteByUserIdAndUsedAtIsNull(USER_ID);
        verify(backupCodeRepository).saveAll(argThat(codes -> {
            int count = 0;
            for (@SuppressWarnings("unused") MfaBackupCode ignored : codes) {
                count++;
            }
            return count == authProperties.getMfa().getBackupCodeCount();
        }));
        verify(tokenStorage).revokeAllSessions(USER_ID.toString());
        verify(securityEventService).recordForAuthenticatedUser(
                SecurityEventType.MFA_CHANGED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                user,
                "totp_enabled");
    }

    @Test
    @DisplayName("MFA verification accepts a fresh TOTP only after atomic replay marker update")
    void verifyMfaCode_acceptsFreshTotpWithAtomicReplayMarker() {
        UUID credentialId = UUID.fromString("00000000-0000-0000-0000-000000000205");
        String secret = Base32.encode("totp-secret-for-test1".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        MfaTotpCredential credential = new MfaTotpCredential(
                USER_ID, TENANT_ID, mfaSecretCipher.encrypt(secret), Instant.now());
        ReflectionTestUtils.setField(credential, "id", credentialId);
        credential.confirm(Instant.now());
        String code = new TotpGenerator().currentCode(secret);

        when(totpRepository.findByUserIdAndConfirmedTrueAndDisabledAtIsNull(USER_ID)).thenReturn(List.of(credential));
        when(totpRepository.markTimeStepUsedIfNewer(eq(credentialId), eq(USER_ID), anyLong())).thenReturn(1);

        var result = service.verifyMfaCode(user, code, "login_mfa");

        assertTrue(result.valid());
        assertEquals("otp", result.method());
        verify(backupCodeRepository, never()).consumeUnusedCode(eq(USER_ID), any(), any());
    }

    @Test
    @DisplayName("Backup codes require active MFA and are consumed atomically")
    void verifyMfaCode_consumesBackupCodeAtomically() {
        UUID credentialId = UUID.fromString("00000000-0000-0000-0000-000000000206");
        String secret = Base32.encode("totp-secret-for-test2".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        MfaTotpCredential credential = new MfaTotpCredential(
                USER_ID, TENANT_ID, mfaSecretCipher.encrypt(secret), Instant.now());
        ReflectionTestUtils.setField(credential, "id", credentialId);
        credential.confirm(Instant.now());
        String rawBackupCode = "ABCD-EFGH-JKLM";
        String expectedHash = auditDigestService.hmacHex("mfa-backup-code|" + USER_ID + "|ABCDEFGHJKLM");

        when(totpRepository.findByUserIdAndConfirmedTrueAndDisabledAtIsNull(USER_ID)).thenReturn(List.of(credential));
        when(backupCodeRepository.consumeUnusedCode(eq(USER_ID), eq(expectedHash), any())).thenReturn(1);

        var result = service.verifyMfaCode(user, rawBackupCode, "session_revocation");

        assertTrue(result.valid());
        assertEquals("backup_code", result.method());
        verify(backupCodeRepository).consumeUnusedCode(eq(USER_ID), eq(expectedHash), any());
        verify(securityEventService).recordForAuthenticatedUser(
                SecurityEventType.MFA_BACKUP_CODE_USED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                user,
                "session_revocation_backup_code_used");
    }

    @Test
    @DisplayName("Backup codes are rejected when no active TOTP credential exists")
    void verifyMfaCode_rejectsBackupCodeWithoutActiveMfa() {
        when(totpRepository.findByUserIdAndConfirmedTrueAndDisabledAtIsNull(USER_ID)).thenReturn(List.of());

        var result = service.verifyMfaCode(user, "ABCD-EFGH-JKLM", "login_mfa");

        assertFalse(result.valid());
        verify(backupCodeRepository, never()).consumeUnusedCode(any(), any(), any());
    }

    @Test
    @DisplayName("Sensitive operations require MFA proof when MFA is enabled")
    void requireMfaIfEnabled_enforcesMfaProof() {
        when(totpRepository.existsByUserIdAndConfirmedTrueAndDisabledAtIsNull(USER_ID)).thenReturn(true);

        assertThrows(MfaRequiredException.class, () ->
                service.requireMfaIfEnabled(user, null, "password_change"));

        verify(securityEventService).recordForAuthenticatedUser(
                SecurityEventType.MFA_CHALLENGE_FAILED,
                SecurityEventOutcome.DENIED,
                SecurityEventSeverity.HIGH,
                user,
                "password_change_mfa_missing");
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("MFA enrollment rejects invalid password step-up before creating credentials")
    void startTotpEnrollment_invalidPasswordStepUpDoesNotCreateCredential() {
        when(passwordEncoder.matches("wrong-pass", "hashed-pass")).thenReturn(false);

        assertThrows(InvalidCredentialsException.class, () ->
                service.startTotpEnrollment(USER_ID.toString(), new StepUpRequest("wrong-pass")));

        verify(totpRepository, never()).save(any());
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("TOTP confirmation rejects invalid codes")
    void confirmTotp_invalidCodeThrows() {
        UUID credentialId = UUID.fromString("00000000-0000-0000-0000-000000000207");
        String secret = Base32.encode("12345678901234567890".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        MfaTotpCredential credential = new MfaTotpCredential(
                USER_ID, TENANT_ID, mfaSecretCipher.encrypt(secret), Instant.now());
        ReflectionTestUtils.setField(credential, "id", credentialId);

        when(totpRepository.findByIdAndUserId(credentialId, USER_ID)).thenReturn(Optional.of(credential));

        assertThrows(InvalidMfaCodeException.class, () ->
                service.confirmTotp(USER_ID.toString(), new MfaTotpConfirmRequest(credentialId, "current-pass", "000000")));

        verify(backupCodeRepository, never()).saveAll(any());
        verify(tokenStorage, never()).revokeAllSessions(USER_ID.toString());
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("TOTP confirmation rejects credentials not owned by the caller")
    void confirmTotp_credentialOwnedByAnotherUser_Throws() {
        UUID credentialId = UUID.fromString("00000000-0000-0000-0000-000000000208");
        when(totpRepository.findByIdAndUserId(credentialId, USER_ID)).thenReturn(Optional.empty());

        assertThrows(InvalidMfaCodeException.class, () ->
                service.confirmTotp(USER_ID.toString(), new MfaTotpConfirmRequest(credentialId, "current-pass", "123456")));

        verify(backupCodeRepository, never()).saveAll(any());
        verify(tokenStorage, never()).revokeAllSessions(USER_ID.toString());
    }

    @Test
    @DisplayName("MFA status hides users outside the authenticated tenant")
    void getStatus_TenantMismatch_Throws404() {
        UUID jwtTenant = UUID.fromString("00000000-0000-0000-0000-000000000209");
        authenticateAsTenant(jwtTenant);

        assertThrows(UserNotFoundException.class, () -> service.getStatus(USER_ID.toString()));
        verify(totpRepository, never()).findByUserIdAndConfirmedTrueAndDisabledAtIsNull(any());
    }

    private void authenticateAsTenant(UUID tenantId) {
        Jwt jwt = new Jwt(
                "token",
                Instant.now(),
                Instant.now().plusSeconds(900),
                Map.of("alg", "none"),
                Map.of("sub", UUID.randomUUID().toString(), "tenant_id", tenantId.toString()));
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
    }
}
