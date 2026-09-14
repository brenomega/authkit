package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doThrow;

import java.util.Optional;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.InvalidTokenException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.infrastructure.email.EmailTemplateRenderer;
import io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectService;
import io.github.brenomega.authkit.service.spi.EmailPayload;

class PasswordRecoveryServiceTest {

    private UserRepository userRepository;
    private TokenStorage tokenStorage;
    private EmailOutboxService emailOutboxService;
    private PasswordEncoder passwordEncoder;
    private AccountLockoutService lockoutService;
    private AuthProperties authProperties;
    private SecurityEventService securityEventService;
    private AbuseThrottleService abuseThrottleService;
    private PasswordPolicyService passwordPolicyService;
    private PasswordRecoveryService recoveryService;
    private SecurityEffectService securityEffects;

    @BeforeEach
    void setUp() {
        TransactionSynchronizationManager.initSynchronization();
        userRepository = mock(UserRepository.class);
        tokenStorage = mock(TokenStorage.class);
        emailOutboxService = mock(EmailOutboxService.class);
        passwordEncoder = mock(PasswordEncoder.class);
        lockoutService = mock(AccountLockoutService.class);
        securityEventService = mock(SecurityEventService.class);
        abuseThrottleService = mock(AbuseThrottleService.class);
        passwordPolicyService = mock(PasswordPolicyService.class);
        securityEffects = mock(SecurityEffectService.class);
        var renderer = mock(EmailTemplateRenderer.class);
        when(renderer.render(any(), any(), any())).thenAnswer(invocation -> {
            Map<?, ?> variables = invocation.getArgument(2);
            return new EmailPayload(
                    invocation.getArgument(1), "subject",
                    variables.containsKey("action_url") ? String.valueOf(variables.get("action_url")) : "notice");
        });
        authProperties = new AuthProperties();
        authProperties.getToken().setRecoveryTokenTtlMinutes(30);
        authProperties.getFrontend().setPasswordResetUrl("https://frontend.example.test/reset-password");
        recoveryService = new PasswordRecoveryService(
                userRepository,
                tokenStorage,
                emailOutboxService,
                passwordEncoder,
                lockoutService,
                authProperties,
                new Argon2ConcurrencyLimiter(),
                securityEventService,
                abuseThrottleService,
                passwordPolicyService,
                renderer,
                securityEffects
        );
    }

    @AfterEach
    void clearTransactionSynchronization() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.getSynchronizations().forEach(
                    synchronization -> synchronization.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    @Test
    @DisplayName("Request: Existing user triggers token and email")
    void requestRecovery_ExistingUser_PublishesEmail() {
        String email = "exists@example.com";
        User user = mock(User.class);
        when(user.getEmail()).thenReturn(email);
        when(user.getPassword()).thenReturn("existing-hash");
        when(userRepository.findByEmailForUpdate(email)).thenReturn(Optional.of(user));

        recoveryService.requestRecovery(email);
        finishSynchronization(TransactionSynchronization.STATUS_COMMITTED);

        verify(securityEffects).activateRecoveryToken(eq(user), any(), eq(30L), any());
        verify(tokenStorage, never()).storeRecoveryToken(any(), any(), anyLong());
        verify(emailOutboxService).enqueueAwaitingActivation(argThat(payload ->
                payload.htmlBody().contains("https://frontend.example.test/reset-password#token=")
                        && payload.htmlBody().contains("&email=exists%40example.com")));
    }

    @Test
    @DisplayName("Request: Non-existing user is handled silently (Stealth)")
    void requestRecovery_NonExistingUser_Silent() {
        String email = "none@example.com";
        when(userRepository.findByEmailForUpdate(email)).thenReturn(Optional.empty());

        recoveryService.requestRecovery(email);

        verify(tokenStorage, never()).storeRecoveryToken(any(), any(), anyLong());
        verify(emailOutboxService, never()).enqueueAwaitingActivation(any());
        verify(securityEffects, never()).activateRecoveryToken(any(), any(), anyLong(), any());
    }

    @Test
    @DisplayName("Request: social-only account cannot silently add a password through email recovery")
    void requestRecovery_SocialOnlyAccount_Silent() {
        String email = "social-only@example.com";
        User user = mock(User.class);
        when(user.getEmail()).thenReturn(email);
        when(user.getPassword()).thenReturn(null);
        when(userRepository.findByEmailForUpdate(email)).thenReturn(Optional.of(user));

        recoveryService.requestRecovery(email);

        verify(tokenStorage, never()).storeRecoveryToken(any(), any(), anyLong());
        verify(emailOutboxService, never()).enqueueAwaitingActivation(any());
        verify(securityEffects, never()).activateRecoveryToken(any(), any(), anyLong(), any());
    }

    @Test
    @DisplayName("Request: outbox rollback never makes its recovery token usable")
    void requestRecovery_OutboxFailureNeverActivatesToken() {
        String email = "rollback@example.com";
        User user = mock(User.class);
        when(user.getEmail()).thenReturn(email);
        when(user.getPassword()).thenReturn("existing-hash");
        when(userRepository.findByEmailForUpdate(email)).thenReturn(Optional.of(user));
        doThrow(new IllegalStateException("outbox unavailable")).when(emailOutboxService).enqueueAwaitingActivation(any());

        assertThrows(IllegalStateException.class, () -> recoveryService.requestRecovery(email));
        finishSynchronization(TransactionSynchronization.STATUS_ROLLED_BACK);

        verify(tokenStorage, never()).storeRecoveryToken(eq(email), any(), anyLong());
    }

    @Test
    @DisplayName("Reset: Valid token successfully changes password")
    void resetPassword_ValidToken_Success() {
        String email = "reset@example.com";
        String token = "valid-token";
        String newPass = "NewPass123!";
        User user = mock(User.class);
        when(user.getEmail()).thenReturn(email);
        when(user.getId()).thenReturn(UUID.fromString("00000000-0000-0000-0000-000000000000"));
        when(user.getPassword()).thenReturn("existing-hash");

        when(tokenStorage.claimRecoveryToken(eq(email), eq(token), any(), eq(1800L))).thenReturn(true);
        when(userRepository.findByEmailForUpdate(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.encode(newPass)).thenReturn("hashed-new-pass");

        recoveryService.resetPassword(email, token, newPass);
        finishSynchronization(TransactionSynchronization.STATUS_COMMITTED);

        verify(userRepository).save(user);

        verify(lockoutService).clearLockout(email);

        verify(securityEffects).invalidateSessions(any(User.class), eq(null));
        verify(securityEffects).revokeRecoveryToken(email);
        verify(emailOutboxService).enqueue(any());
    }

    @Test
    @DisplayName("Reset: Invalid token throws exception")
    void resetPassword_InvalidToken_ThrowsException() {
        when(tokenStorage.claimRecoveryToken(any(), any(), any(), eq(1800L))).thenReturn(false);

        assertThrows(InvalidTokenException.class, () ->
            recoveryService.resetPassword("any@example.com", "bad", "new"));
    }

    @Test
    @DisplayName("Reset: Valid token but missing user throws exception")
    void resetPassword_MissingUser_ThrowsException() {
        String email = "gone@example.com";
        when(tokenStorage.claimRecoveryToken(eq(email), any(), any(), eq(1800L))).thenReturn(true);
        when(userRepository.findByEmailForUpdate(email)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () ->
            recoveryService.resetPassword(email, "token", "pass"));
    }

    private void finishSynchronization(int status) {
        var synchronizations = TransactionSynchronizationManager.getSynchronizations();
        if (status == TransactionSynchronization.STATUS_COMMITTED) {
            synchronizations.forEach(TransactionSynchronization::afterCommit);
        }
        synchronizations.forEach(synchronization -> synchronization.afterCompletion(status));
        TransactionSynchronizationManager.clearSynchronization();
        TransactionSynchronizationManager.initSynchronization();
    }
}
