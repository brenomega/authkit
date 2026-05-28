package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.exception.InvalidTokenException;
import io.github.brenomega.authkit.exception.UserAlreadyExistsException;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
class RegistrationServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private EmailOutboxService emailOutboxService;

    private RegistrationService service;
    private AuthProperties authProperties;
    private SecurityEventService securityEventService;
    private ConsentEventService consentEventService;
    private AbuseThrottleService abuseThrottleService;
    private PasswordPolicyService passwordPolicyService;

    @BeforeEach
    void setUp() {
        authProperties = new AuthProperties();
        authProperties.getFrontend().setActivationUrl("https://frontend.example.test/activate");
        authProperties.getCompliance().setTermsVersion("terms-2026");
        authProperties.getCompliance().setPrivacyPolicyVersion("privacy-2026");
        securityEventService = org.mockito.Mockito.mock(SecurityEventService.class);
        consentEventService = org.mockito.Mockito.mock(ConsentEventService.class);
        abuseThrottleService = org.mockito.Mockito.mock(AbuseThrottleService.class);
        passwordPolicyService = org.mockito.Mockito.mock(PasswordPolicyService.class);
        service = new RegistrationService(
                userRepository,
                passwordEncoder,
                emailOutboxService,
                authProperties,
                securityEventService,
                consentEventService,
                abuseThrottleService,
                passwordPolicyService);
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Registers user successfully, hashes password, generates tenantId and queues email")
    void registerUser_success() {
        RegisterRequest request = new RegisterRequest(
                "new@example.com", "Password123!", true, true);

        when(userRepository.findByEmail("new@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("Password123!")).thenReturn("hashedPwd");
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        User user = service.registerUser(request);

        assertNotNull(user);
        assertNotNull(user.getTenantId(), "Multi-tenancy ID must be generated");
        assertFalse(user.isEmailConfirmed(), "Email must not be confirmed yet");
        assertNotNull(user.getEmailConfirmationExpiresAt(), "Email confirmation token must expire");
        assertEquals("terms-2026", user.getTermsVersion());
        assertEquals("privacy-2026", user.getPrivacyPolicyVersion());
        assertEquals("consent", user.getLawfulBasis());
        assertNotNull(user.getConsentAcceptedAt());

        verify(emailOutboxService).enqueue(argThat(payload ->
                payload.to().equals("new@example.com") &&
                payload.htmlBody().contains("https://frontend.example.test/activate?token=")
        ));
        verify(consentEventService).recordCurrentConsent(user);
    }

    @Test
    @DisplayName("Fails registration if email is already in use")
    void registerUser_conflict() {
        RegisterRequest request = new RegisterRequest(
                "existing@example.com", "Password123!", true, true);

        User existingUser = new User("existing@example.com", "pw", null, null, true, true, null);
        when(userRepository.findByEmail("existing@example.com")).thenReturn(Optional.of(existingUser));

        assertThrows(UserAlreadyExistsException.class, () -> service.registerUser(request));
    }

    @Test
    @DisplayName("Email confirmation marks account confirmed and consumes activation token")
    void confirmEmail_success() {
        String rawToken = "activation-token";
        String tokenHash = TokenHasher.sha256Hex(rawToken);
        User user = new User("confirm@example.com", "pw", null, null, true, true, tokenHash);
        user.setEmailConfirmationExpiresAt(Instant.now().plusSeconds(300));
        when(userRepository.findByEmailConfirmationToken(tokenHash)).thenReturn(Optional.of(user));

        service.confirmEmail(rawToken);

        assertTrue(user.isEmailConfirmed());
        assertNull(user.getEmailConfirmationToken());
        assertNull(user.getEmailConfirmationExpiresAt());
        verify(userRepository).save(user);
    }

    @Test
    @DisplayName("Email confirmation rejects expired tokens and invalidates them")
    void confirmEmail_expiredToken() {
        String rawToken = "expired-token";
        String tokenHash = TokenHasher.sha256Hex(rawToken);
        User user = new User("expired@example.com", "pw", null, null, true, true, tokenHash);
        user.setEmailConfirmationExpiresAt(Instant.now().minusSeconds(1));
        when(userRepository.findByEmailConfirmationToken(tokenHash)).thenReturn(Optional.of(user));

        assertThrows(InvalidTokenException.class, () -> service.confirmEmail(rawToken));

        assertNull(user.getEmailConfirmationToken());
        assertNull(user.getEmailConfirmationExpiresAt());
        verify(userRepository).save(user);
    }

    @Test
    @DisplayName("Resending email confirmation rotates the token and queues a new message")
    void resendEmailConfirmation_rotatesToken() {
        User user = new User("resend@example.com", "pw", null, null, true, true, "old-token-hash");
        user.setEmailConfirmationExpiresAt(Instant.now().plusSeconds(60));
        when(userRepository.findByEmail("resend@example.com")).thenReturn(Optional.of(user));

        service.resendEmailConfirmation("resend@example.com");

        assertNotNull(user.getEmailConfirmationToken());
        assertNotNull(user.getEmailConfirmationExpiresAt());
        org.junit.jupiter.api.Assertions.assertNotEquals("old-token-hash", user.getEmailConfirmationToken());
        verify(userRepository).save(user);
        verify(emailOutboxService).enqueue(argThat(payload ->
                payload.to().equals("resend@example.com")
                        && payload.htmlBody().contains("https://frontend.example.test/activate?token=")));
    }

    @Test
    @DisplayName("Email confirmation rejects invalid or expired tokens")
    void confirmEmail_invalidToken() {
        String rawToken = "bad-token";
        when(userRepository.findByEmailConfirmationToken(TokenHasher.sha256Hex(rawToken))).thenReturn(Optional.empty());

        assertThrows(InvalidTokenException.class,
                () -> service.confirmEmail(rawToken));
    }
}
