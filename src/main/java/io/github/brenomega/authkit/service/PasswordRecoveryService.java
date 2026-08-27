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
 * Service for handling password recovery workflows (RF 2.1.3, RF 2.1.4).
 *
 * <p>Implements the "stealth" initiation strategy (DT 3.2.15) and
 * secure token-based reset with infrastructure integration.</p>
 *
 * <p><strong>Lockout Integration (DT 3.2.23):</strong> A successful password
 * reset is the <strong>only</strong> sanctioned path to clear the progressive
 * lockout counter and unlock a frozen account.</p>
 *
 * <p><strong>Session Revocation (RF 2.1.12):</strong> All active refresh tokens
 * are revoked upon password reset to force re-authentication.</p>
 *
 * @see AccountLockoutService
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
            EmailTemplateRenderer emailTemplateRenderer) {
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
    }

    /**
     * Initiates the password recovery flow (RF 2.1.3).
     *
     * <p><strong>Stealth Strategy (DT 3.2.15):</strong> Always returns success
     * regardless of account existence to prevent enumeration.</p>
     *
     * @param email the email to send the recovery link to
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
                    tokenStorage.storeRecoveryToken(normalizedEmail, token, ttlMinutes);
                    registerRecoveryRequestCompensation(normalizedEmail, token);
                    
                    String resetLink = authProperties.getFrontend().getPasswordResetUrl()
                            + "#token=" + URLEncoder.encode(token, StandardCharsets.UTF_8)
                            + "&email=" + URLEncoder.encode(normalizedEmail, StandardCharsets.UTF_8);
                    EmailPayload emailPayload = emailTemplateRenderer.render(
                            EmailTemplateId.PASSWORD_RECOVERY, normalizedEmail, Map.of("action_url", resetLink));
                    emailOutboxService.enqueue(emailPayload);
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
     * Resets the user's password using a valid token (RF 2.1.4).
     *
     * @param email       the user's email
     * @param token       the recovery token
     * @param newPassword the new password
     * @throws IllegalArgumentException if the token is invalid or expired
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

        User user = userRepository.findByEmail(normalizedEmail)
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

        // Password recovery proves control of an email channel, not authority to add a
        // new local authenticator to a social-only account.
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

        // DT 3.2.23: Clear progressive lockout — this is the ONLY unlock path
        lockoutService.clearLockout(normalizedEmail);

        // RF 2.1.12: Revoke all active sessions to force re-authentication
        tokenStorage.revokeAllSessions(user.getId().toString());

        EmailPayload confirmation = emailTemplateRenderer.render(
                EmailTemplateId.PASSWORD_CHANGED, normalizedEmail, Map.of());
        emailOutboxService.enqueue(confirmation);

        securityEventService.recordForTargetUser(
                SecurityEventType.PASSWORD_RESET_COMPLETED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                user,
                "password_reset_completed");

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

    private void registerRecoveryRequestCompensation(String email, String rawToken) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            tokenStorage.revokeRecoveryTokenIfMatches(email, rawToken);
            throw new IllegalStateException("Password recovery request requires an active transaction");
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                if (status != STATUS_COMMITTED) {
                    try {
                        tokenStorage.revokeRecoveryTokenIfMatches(email, rawToken);
                    } catch (RuntimeException ex) {
                        log.error("Recovery-token rollback compensation failed.", ex);
                    }
                }
            }
        });
    }
}
