package io.github.brenomega.authkit.service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.exception.AuthenticationCapacityExceededException;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.exception.InvalidTokenException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.infrastructure.aop.LogExecutionTime;
import io.github.brenomega.authkit.infrastructure.persistence.AfterCommitActions;
import io.github.brenomega.authkit.infrastructure.persistence.securityeffects.SecurityEffectService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.queue.outbox.EmailOutboxService;
import io.github.brenomega.authkit.infrastructure.email.EmailTemplateRenderer;
import io.github.brenomega.authkit.infrastructure.email.EmailTemplateId;
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;
import io.github.brenomega.authkit.infrastructure.security.AbuseRateLimitPolicy;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.EmailPayload;
import io.github.brenomega.authkit.service.spi.TokenStorage;

/**
 * Coordinates enumeration-resistant password recovery and one-time reset consumption.
 *
 * <p>Recovery requests expose the same outward result for absent accounts and do
 * not create a password authenticator for social-only accounts. Raw recovery
 * secrets are represented only by digests in {@link TokenStorage}. Activation
 * intent and an email waiting for activation commit together; rollback publishes
 * neither. Failed activation is reconciled durably before dispatch.</p>
 *
 * <p>A reset first claims the token so concurrent attempts cannot both change the
 * password. Commit permanently consumes the claim, while rollback releases it for
 * a later retry. A successful reset checks password policy and history, clears
 * lockout state, and revokes every existing session.</p>
 */
@Service
public class PasswordRecoveryService {

    private static final Logger log = LoggerFactory.getLogger(PasswordRecoveryService.class);

    private final UserRepository userRepository;
    private final TokenStorage tokenStorage;
    private final EmailOutboxService emailOutboxService;
    private final PasswordEncoder passwordEncoder;
    private final AccountLockoutService lockoutService;
    private final AuthProperties authProperties;
    private final Argon2ConcurrencyLimiter argon2Limiter;
    private final SecurityEventService securityEventService;
    private final AbuseThrottleService abuseThrottleService;
    private final PasswordPolicyService passwordPolicyService;
    private final EmailTemplateRenderer emailTemplateRenderer;
    private final SecurityEffectService securityEffectService;

    public PasswordRecoveryService(
            UserRepository userRepository,
            TokenStorage tokenStorage,
            EmailOutboxService emailOutboxService,
            PasswordEncoder passwordEncoder,
            AccountLockoutService lockoutService,
            AuthProperties authProperties,
            Argon2ConcurrencyLimiter argon2Limiter,
            SecurityEventService securityEventService,
            AbuseThrottleService abuseThrottleService,
            PasswordPolicyService passwordPolicyService,
            EmailTemplateRenderer emailTemplateRenderer,
            SecurityEffectService securityEffectService) {
        this.userRepository = userRepository;
        this.tokenStorage = tokenStorage;
        this.emailOutboxService = emailOutboxService;
        this.passwordEncoder = passwordEncoder;
        this.lockoutService = lockoutService;
        this.authProperties = authProperties;
        this.argon2Limiter = argon2Limiter;
        this.securityEventService = securityEventService;
        this.abuseThrottleService = abuseThrottleService;
        this.passwordPolicyService = passwordPolicyService;
        this.emailTemplateRenderer = emailTemplateRenderer;
        this.securityEffectService = securityEffectService;
    }

    /**
     * Requests recovery without disclosing whether the normalized email can recover a password.
     *
     * <p>For an eligible account, the durable notification is committed first;
     * the recovery token cannot become usable until that SQL commit succeeds.</p>
     */
    @LogExecutionTime
    @Transactional
    public void requestRecovery(String email) {
        String normalizedEmail = EmailNormalizer.normalize(email);
        abuseThrottleService.checkEmail(AbuseRateLimitPolicy.PASSWORD_RECOVERY_EMAIL_COOLDOWN, normalizedEmail);
        abuseThrottleService.checkEmail(AbuseRateLimitPolicy.PASSWORD_RECOVERY_EMAIL_DAILY, normalizedEmail);

        userRepository.findByEmailForUpdate(normalizedEmail).ifPresentOrElse(
                user -> {
                    if (user.getPassword() == null) {
                        securityEventService.recordForTargetUser(
                                SecurityEventType.PASSWORD_RESET_REQUESTED,
                                SecurityEventOutcome.INFO,
                                SecurityEventSeverity.MEDIUM,
                                user,
                                "password_reset_unavailable_for_social_only_account");
                        return;
                    }
                    securityEventService.recordForTargetUser(
                            SecurityEventType.PASSWORD_RESET_REQUESTED,
                            SecurityEventOutcome.INFO,
                            SecurityEventSeverity.MEDIUM,
                            user,
                            "password_reset_requested");
                    String token = SecureTokenGenerator.randomUrlSafeToken(32);
                    long ttlMinutes = authProperties.getToken().getRecoveryTokenTtlMinutes();
                    String resetLink = authProperties.getFrontend().getPasswordResetUrl()
                            + "#token=" + URLEncoder.encode(token, StandardCharsets.UTF_8)
                            + "&email=" + URLEncoder.encode(normalizedEmail, StandardCharsets.UTF_8);
                    EmailPayload emailPayload = emailTemplateRenderer.render(
                            EmailTemplateId.PASSWORD_RECOVERY, normalizedEmail, Map.of("action_url", resetLink));
                    UUID messageId = emailOutboxService.enqueueAwaitingActivation(emailPayload);
                    securityEffectService.activateRecoveryToken(user, token, ttlMinutes, messageId);
                    log.info("Password recovery requested for existing user. Token generated and event published.");
                },
                () -> {
                    securityEventService.recordForEmail(
                            SecurityEventType.PASSWORD_RESET_REQUESTED,
                            SecurityEventOutcome.INFO,
                            SecurityEventSeverity.MEDIUM,
                            normalizedEmail,
                            "password_reset_requested_stealth");
                    log.info("Password recovery requested for non-existing account. Stealth response triggered.");
                }
        );
    }

    /**
     * Replaces the existing password after exclusively claiming a valid recovery token.
     *
     * <p>The token is consumed only after the database transaction commits and is
     * released when it rolls back. Concurrent reset attempts therefore cannot both
     * pass the claim boundary.</p>
     *
     * @throws InvalidTokenException if the token is invalid, expired, already claimed,
     *         or cannot be used by the account
     */
    @Transactional
    @LogExecutionTime
    public void resetPassword(String email, String token, String newPassword) {
        String normalizedEmail = EmailNormalizer.normalize(email);
        abuseThrottleService.checkEmail(AbuseRateLimitPolicy.PASSWORD_RESET_EMAIL, normalizedEmail);

        String claimId = UUID.randomUUID().toString();
        long claimTtlSeconds = Math.multiplyExact(
                authProperties.getToken().getRecoveryTokenTtlMinutes(), 60L);
        if (!tokenStorage.claimRecoveryToken(normalizedEmail, token, claimId, claimTtlSeconds)) {
            log.warn("Invalid or expired password recovery token.");
            securityEventService.recordForEmail(
                    SecurityEventType.PASSWORD_RESET_FAILED,
                    SecurityEventOutcome.FAILURE,
                    SecurityEventSeverity.HIGH,
                    normalizedEmail,
                    "invalid_or_expired_reset_token");
            throw new InvalidTokenException();
        }
        registerRecoveryClaimCompletion(normalizedEmail, claimId);

        User user = userRepository.findByEmailForUpdate(normalizedEmail)
                .orElseThrow(() -> {
                    securityEventService.recordForEmail(
                            SecurityEventType.PASSWORD_RESET_FAILED,
                            SecurityEventOutcome.FAILURE,
                            SecurityEventSeverity.HIGH,
                            normalizedEmail,
                            "reset_user_not_found");
                    return new UserNotFoundException();
                });

        if (user.isDeleted()) {
            securityEventService.recordForEmail(
                    SecurityEventType.PASSWORD_RESET_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    normalizedEmail,
                    "deleted_account");
            throw new UserNotFoundException();
        }

        if (user.getPassword() == null) {
            securityEventService.recordForTargetUser(
                    SecurityEventType.PASSWORD_RESET_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    "password_recovery_cannot_add_authenticator");
            throw new InvalidTokenException();
        }

        passwordPolicyService.validateForUser(user, newPassword);
        passwordPolicyService.recordCurrentPassword(user);
        user.setPassword(encodeWithCapacity(newPassword));
        userRepository.save(user);

        EmailPayload confirmation = emailTemplateRenderer.render(
                EmailTemplateId.PASSWORD_CHANGED, normalizedEmail, Map.of());
        emailOutboxService.enqueue(confirmation);

        securityEventService.recordForTargetUser(
                SecurityEventType.PASSWORD_RESET_COMPLETED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                user,
                "password_reset_completed");

        securityEffectService.invalidateSessions(user, null);
        // The claim-completion callback is the fast path. This committed outbox
        // intent guarantees the recovery token and claim cannot become usable
        // again after their Redis claim TTL when Redis is unavailable at commit.
        securityEffectService.revokeRecoveryToken(normalizedEmail);
        AfterCommitActions.run(() -> lockoutService.clearLockout(normalizedEmail));

        log.info("Password successfully reset for user: {}", user.getId());
    }

    private String encodeWithCapacity(String rawPassword) {
        boolean acquired = argon2Limiter.tryAcquire();
        if (!acquired) {
            throw new AuthenticationCapacityExceededException();
        }

        try {
            return passwordEncoder.encode(rawPassword);
        } finally {
            argon2Limiter.release();
        }
    }

    private void registerRecoveryClaimCompletion(String email, String claimId) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            tokenStorage.releaseRecoveryTokenClaim(email, claimId);
            throw new IllegalStateException("Password recovery requires an active transaction");
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                try {
                    if (status == STATUS_COMMITTED) {
                        tokenStorage.completeRecoveryTokenClaim(email, claimId);
                    } else {
                        tokenStorage.releaseRecoveryTokenClaim(email, claimId);
                    }
                } catch (RuntimeException ex) {
                    log.error("Recovery-token claim reconciliation failed after transaction completion.", ex);
                }
            }
        });
    }

}
