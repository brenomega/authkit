package io.github.brenomega.authkit.service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.github.brenomega.authkit.domain.user.dto.EmailChangeRequest;
import io.github.brenomega.authkit.domain.user.dto.EmailChangeStatusResponse;
import io.github.brenomega.authkit.domain.user.dto.StepUpRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.exception.InvalidTokenException;
import io.github.brenomega.authkit.exception.UserAlreadyExistsException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.email.EmailTemplateRenderer;
import io.github.brenomega.authkit.infrastructure.email.EmailTemplateId;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.security.UserAuthoritiesFilter;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

/** Durable, one-time secure email-change ceremony. */
@Service
public class EmailChangeService {

    private final UserRepository userRepository;
    private final StepUpService stepUpService;
    private final MfaService mfaService;
    private final EmailOutboxService emailOutboxService;
    private final SecurityEventService securityEventService;
    private final TokenStorage tokenStorage;
    private final UserAuthoritiesFilter userAuthoritiesFilter;
    private final AuthProperties authProperties;
    private final EmailTemplateRenderer emailTemplateRenderer;

    public EmailChangeService(UserRepository userRepository,
                              StepUpService stepUpService,
                              MfaService mfaService,
                              EmailOutboxService emailOutboxService,
                              SecurityEventService securityEventService,
                              TokenStorage tokenStorage,
                              UserAuthoritiesFilter userAuthoritiesFilter,
                              AuthProperties authProperties,
                              EmailTemplateRenderer emailTemplateRenderer) {
        this.userRepository = userRepository;
        this.stepUpService = stepUpService;
        this.mfaService = mfaService;
        this.emailOutboxService = emailOutboxService;
        this.securityEventService = securityEventService;
        this.tokenStorage = tokenStorage;
        this.userAuthoritiesFilter = userAuthoritiesFilter;
        this.authProperties = authProperties;
        this.emailTemplateRenderer = emailTemplateRenderer;
    }

    @Transactional
    public EmailChangeStatusResponse request(String userId, EmailChangeRequest request) {
        User user = loadActiveUser(userId);
        String newEmail = EmailNormalizer.normalize(request.newEmail());
        stepUpService.verifyCurrentPassword(
                user, request.currentPassword(), SecurityEventType.EMAIL_CHANGE_FAILED, "email_change_step_up_failed");
        mfaService.requireMfaIfEnabled(user, request.mfaCode(), "email_change");

        if (newEmail.equals(user.getEmail()) || userRepository.findByEmail(newEmail).isPresent()
                || userRepository.existsByPendingEmail(newEmail)) {
            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.EMAIL_CHANGE_FAILED, SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH, user, "email_change_address_unavailable");
            throw new UserAlreadyExistsException("Email already in use");
        }

        String rawToken = SecureTokenGenerator.randomUrlSafeToken(32);
        Instant requestedAt = Instant.now();
        Instant expiresAt = requestedAt.plus(Duration.ofHours(
                authProperties.getRegistration().getEmailChangeTtlHours()));
        user.requestEmailChange(newEmail, TokenHasher.sha256Hex(rawToken), requestedAt, expiresAt);
        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException ex) {
            throw new UserAlreadyExistsException("Email already in use");
        }

        String actionUrl = authProperties.getFrontend().getEmailChangeUrl()
                + "#token=" + URLEncoder.encode(rawToken, StandardCharsets.UTF_8);
        emailOutboxService.enqueue(emailTemplateRenderer.render(
                EmailTemplateId.EMAIL_CHANGE_CONFIRMATION, newEmail, Map.of("action_url", actionUrl)));
        emailOutboxService.enqueue(emailTemplateRenderer.render(
                EmailTemplateId.EMAIL_CHANGE_REQUESTED, user.getEmail(), Map.of()));
        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.EMAIL_CHANGE_REQUESTED, SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH, user, "email_change_requested",
                Map.of("expires_in_hours", Long.toString(authProperties.getRegistration().getEmailChangeTtlHours())));

        return status(user, "pending_confirmation");
    }

    @Transactional(noRollbackFor = InvalidTokenException.class)
    public void confirm(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            recordInvalidTokenFailure();
            throw new InvalidTokenException();
        }
        User user = userRepository.findByEmailChangeTokenHashForUpdate(TokenHasher.sha256Hex(rawToken))
                .orElseThrow(() -> {
                    recordInvalidTokenFailure();
                    return new InvalidTokenException();
                });
        if (user.getEmailChangeExpiresAt() == null || !user.getEmailChangeExpiresAt().isAfter(Instant.now())) {
            user.clearPendingEmailChange();
            userRepository.save(user);
            securityEventService.recordForTargetUser(
                    SecurityEventType.EMAIL_CHANGE_FAILED, SecurityEventOutcome.FAILURE,
                    SecurityEventSeverity.HIGH, user, "email_change_token_expired");
            throw new InvalidTokenException();
        }

        String newEmail = user.getPendingEmail();
        if (userRepository.findByEmail(newEmail).filter(other -> !other.getId().equals(user.getId())).isPresent()) {
            securityEventService.recordForTargetUser(
                    SecurityEventType.EMAIL_CHANGE_FAILED, SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH, user, "email_change_address_unavailable_at_commit");
            throw new UserAlreadyExistsException("Email already in use");
        }

        String oldEmail = user.completeEmailChange();
        try {
            userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException ex) {
            throw new UserAlreadyExistsException("Email already in use");
        }

        tokenStorage.revokeAllSessions(user.getId().toString());
        tokenStorage.revokeRecoveryToken(oldEmail);
        tokenStorage.revokeRecoveryToken(newEmail);
        userAuthoritiesFilter.evict(user.getId());
        emailOutboxService.enqueue(emailTemplateRenderer.render(
                EmailTemplateId.EMAIL_CHANGED, oldEmail, Map.of()));
        securityEventService.record(
                SecurityEventType.EMAIL_CHANGE_COMPLETED, SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH, user.getId(), user.getId(), user.getTenantId(),
                newEmail, "email_change_completed", Map.of());
    }

    @Transactional
    public EmailChangeStatusResponse cancel(String userId, StepUpRequest request) {
        User user = loadActiveUser(userId);
        stepUpService.verifyCurrentPassword(
                user, request.currentPassword(), SecurityEventType.EMAIL_CHANGE_FAILED, "email_change_cancel_step_up_failed");
        mfaService.requireMfaIfEnabled(user, request.mfaCode(), "email_change_cancel");
        user.cancelEmailChange();
        userRepository.save(user);
        emailOutboxService.enqueue(emailTemplateRenderer.render(
                EmailTemplateId.EMAIL_CHANGE_CANCELLED, user.getEmail(), Map.of()));
        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.EMAIL_CHANGE_CANCELLED, SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH, user, "email_change_cancelled");
        return status(user, "cancelled");
    }

    private User loadActiveUser(String userId) {
        User user = userRepository.findById(UUID.fromString(userId)).orElseThrow(UserNotFoundException::new);
        user.requireEmailConfirmed();
        return user;
    }

    private void recordInvalidTokenFailure() {
        securityEventService.record(
                SecurityEventType.EMAIL_CHANGE_FAILED, SecurityEventOutcome.FAILURE,
                SecurityEventSeverity.HIGH, null, null, null, null,
                "invalid_email_change_token", Map.of());
    }

    private EmailChangeStatusResponse status(User user, String state) {
        return new EmailChangeStatusResponse(
                state, user.getPendingEmail(), user.getEmailChangeRequestedAt(), user.getEmailChangeExpiresAt());
    }
}
