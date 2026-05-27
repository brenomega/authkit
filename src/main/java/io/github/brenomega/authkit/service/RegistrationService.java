package io.github.brenomega.authkit.service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.exception.InvalidTokenException;
import io.github.brenomega.authkit.exception.UserAlreadyExistsException;
import io.github.brenomega.authkit.infrastructure.audit.ConsentEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.dto.EmailPayload;
import io.github.brenomega.authkit.infrastructure.aop.LogExecutionTime;

/**
 * Service handling the user registration and activation flow.
 */
@Service
public class RegistrationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailOutboxService emailOutboxService;
    private final AuthProperties authProperties;
    private final SecurityEventService securityEventService;
    private final ConsentEventService consentEventService;

    public RegistrationService(UserRepository userRepository,
                               PasswordEncoder passwordEncoder,
                               EmailOutboxService emailOutboxService,
                               AuthProperties authProperties,
                               SecurityEventService securityEventService,
                               ConsentEventService consentEventService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailOutboxService = emailOutboxService;
        this.authProperties = authProperties;
        this.securityEventService = securityEventService;
        this.consentEventService = consentEventService;
    }

    /**
     * Registers a new user with multi-tenancy and async email activation.
     *
     * @param request defined by the DTO whitelist
     * @return the saved entity
     */
    @Transactional
    @LogExecutionTime
    public User registerUser(RegisterRequest request) {
        String email = EmailNormalizer.normalize(request.email());

        if (userRepository.findByEmail(email).isPresent()) {
            throw new UserAlreadyExistsException("Email already in use");
        }

        String hashedPassword = passwordEncoder.encode(request.password());
        ConfirmationToken confirmationToken = newConfirmationToken();

        User user = new User(
                email,
                hashedPassword,
                null,
                null,
                request.termsAccepted(),
                request.privacyPolicyAccepted(),
                confirmationToken.hash()
        );
        user.setEmailConfirmationExpiresAt(confirmationToken.expiresAt());
        user.recordConsent(
                authProperties.getCompliance().getTermsVersion(),
                authProperties.getCompliance().getPrivacyPolicyVersion(),
                authProperties.getCompliance().getLawfulBasis(),
                java.time.Instant.now());

        try {
            user = userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            throw new UserAlreadyExistsException("Email already in use");
        }
        consentEventService.recordCurrentConsent(user);

        enqueueActivationEmail(user, confirmationToken.raw());

        return user;
    }

    /**
     * Confirms a user's email address using the one-time activation token.
     */
    @SuppressWarnings("null")
    @Transactional
    @LogExecutionTime
    public void confirmEmail(String token) {
        if (token == null || token.isBlank()) {
            throw new InvalidTokenException();
        }

        String tokenHash = TokenHasher.sha256Hex(token);
        User user = userRepository.findByEmailConfirmationToken(tokenHash)
                .orElseThrow(InvalidTokenException::new);
        if (user.getEmailConfirmationExpiresAt() == null || !user.getEmailConfirmationExpiresAt().isAfter(Instant.now())) {
            user.setEmailConfirmationToken(null);
            user.setEmailConfirmationExpiresAt(null);
            userRepository.save(user);
            throw new InvalidTokenException();
        }

        user.setEmailConfirmed(true);
        user.setEmailConfirmationToken(null);
        user.setEmailConfirmationExpiresAt(null);
        userRepository.save(user);
        securityEventService.recordForTargetUser(
                SecurityEventType.EMAIL_VERIFIED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "email_verified");
    }

    @Transactional
    @LogExecutionTime
    public void resendEmailConfirmation(String emailInput) {
        String email = EmailNormalizer.normalize(emailInput);
        userRepository.findByEmail(email)
                .filter(user -> !user.isDeleted())
                .filter(user -> !user.isEmailConfirmed())
                .ifPresent(user -> {
                    ConfirmationToken confirmationToken = newConfirmationToken();
                    user.setEmailConfirmationToken(confirmationToken.hash());
                    user.setEmailConfirmationExpiresAt(confirmationToken.expiresAt());
                    userRepository.save(user);
                    enqueueActivationEmail(user, confirmationToken.raw());
                    securityEventService.recordForTargetUser(
                            SecurityEventType.EMAIL_VERIFIED,
                            SecurityEventOutcome.INFO,
                            SecurityEventSeverity.LOW,
                            user,
                            "email_confirmation_resent");
                });
    }

    private ConfirmationToken newConfirmationToken() {
        String raw = SecureTokenGenerator.randomUrlSafeToken(32);
        Instant expiresAt = Instant.now().plus(Duration.ofHours(
                authProperties.getRegistration().getEmailConfirmationTtlHours()));
        return new ConfirmationToken(raw, TokenHasher.sha256Hex(raw), expiresAt);
    }

    private void enqueueActivationEmail(User user, String rawToken) {
        String activationUrl = authProperties.getFrontend().getActivationUrl()
                + "?token=" + URLEncoder.encode(rawToken, StandardCharsets.UTF_8);
        EmailPayload payload = new EmailPayload(
                user.getEmail(),
                "Welcome to AuthKit - Activate your account",
                "<p>Click <a href='" + activationUrl + "'>here</a> to activate your account.</p>"
        );

        emailOutboxService.enqueue(payload);
    }

    private record ConfirmationToken(String raw, String hash, Instant expiresAt) {
    }
}
