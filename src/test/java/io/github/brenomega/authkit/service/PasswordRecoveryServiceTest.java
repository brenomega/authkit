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

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.InvalidTokenException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;

/**
 * Unit tests for PasswordRecoveryService (DT 3.4.5).
 * Validates RF 2.1.3 and RF 2.1.4.
 */
class PasswordRecoveryServiceTest {

    private UserRepository userRepository;
    private TokenStorage tokenStorage;
    private EmailOutboxService emailOutboxService;
    private PasswordEncoder passwordEncoder;
    private AccountLockoutService lockoutService;
    private AuthProperties authProperties;
    private PasswordRecoveryService recoveryService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        tokenStorage = mock(TokenStorage.class);
        emailOutboxService = mock(EmailOutboxService.class);
        passwordEncoder = mock(PasswordEncoder.class);
        lockoutService = mock(AccountLockoutService.class);
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
                new Argon2ConcurrencyLimiter()
        );
    }

    /**
     * RF 2.1.3 — Recovery Initiation: Confirms token generation and email dispatch for valid users.
     */
    @Test
    @DisplayName("Request: Existing user triggers token and email")
    void requestRecovery_ExistingUser_PublishesEmail() {
        String email = "exists@example.com";
        User user = mock(User.class);
        when(user.getEmail()).thenReturn(email);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        recoveryService.requestRecovery(email);

        verify(tokenStorage).storeRecoveryToken(eq(email), any(), eq(30L));
        verify(emailOutboxService).enqueue(argThat(payload ->
                payload.htmlBody().contains("https://frontend.example.test/reset-password?token=")
                        && payload.htmlBody().contains("&email=exists%40example.com")));
    }

    /**
     * DT 3.2.15 — Stealth Initiation: Confirms no email or token for non-existing users (silent ignore).
     */
    @Test
    @DisplayName("Request: Non-existing user is handled silently (Stealth)")
    void requestRecovery_NonExistingUser_Silent() {
        String email = "none@example.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        recoveryService.requestRecovery(email);

        verify(tokenStorage, never()).storeRecoveryToken(any(), any(), anyLong());
        verify(emailOutboxService, never()).enqueue(any());
    }

    /**
     * RF 2.1.4 — Password Reset: Validates successful reset cycle.
     */
    @Test
    @DisplayName("Reset: Valid token successfully changes password")
    void resetPassword_ValidToken_Success() {
        String email = "reset@example.com";
        String token = "valid-token";
        String newPass = "NewPass123!";
        User user = mock(User.class);
        when(user.getEmail()).thenReturn(email);
        when(user.getId()).thenReturn(java.util.UUID.fromString("00000000-0000-0000-0000-000000000000"));

        when(tokenStorage.consumeRecoveryToken(email, token)).thenReturn(true);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.encode(newPass)).thenReturn("hashed-new-pass");

        recoveryService.resetPassword(email, token, newPass);

        verify(userRepository).save(user);
        // DT 3.2.23: Lockout must be cleared after successful reset
        verify(lockoutService).clearLockout(email);
        // RF 2.1.12: All sessions must be revoked after password reset
        verify(tokenStorage).revokeAllSessions("00000000-0000-0000-0000-000000000000");
        verify(emailOutboxService).enqueue(any()); // Reset confirmation
    }

    /**
     * Edge Case: Invalid token should throw InvalidTokenException (HTTP 400).
     */
    @Test
    @DisplayName("Reset: Invalid token throws exception")
    void resetPassword_InvalidToken_ThrowsException() {
        when(tokenStorage.consumeRecoveryToken(any(), any())).thenReturn(false);

        assertThrows(InvalidTokenException.class, () -> 
            recoveryService.resetPassword("any@example.com", "bad", "new"));
    }

    /**
     * Edge Case: Valid token but user deleted/missing should throw UserNotFoundException.
     */
    @Test
    @DisplayName("Reset: Valid token but missing user throws exception")
    void resetPassword_MissingUser_ThrowsException() {
        String email = "gone@example.com";
        when(tokenStorage.consumeRecoveryToken(eq(email), any())).thenReturn(true);
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> 
            recoveryService.resetPassword(email, "token", "pass"));
    }
}
