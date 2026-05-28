package io.github.brenomega.authkit.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.AccountLockedException;
import io.github.brenomega.authkit.exception.AuthenticationCapacityExceededException;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AbuseRateLimitPolicy;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;

/**
 * Centralized current-password step-up verification for sensitive operations.
 */
@Service
public class StepUpService {

    private final PasswordEncoder passwordEncoder;
    private final Argon2ConcurrencyLimiter argon2Limiter;
    private final AccountLockoutService lockoutService;
    private final SecurityEventService securityEventService;
    private final AbuseThrottleService abuseThrottleService;

    public StepUpService(PasswordEncoder passwordEncoder,
                         Argon2ConcurrencyLimiter argon2Limiter,
                         AccountLockoutService lockoutService,
                         SecurityEventService securityEventService,
                         AbuseThrottleService abuseThrottleService) {
        this.passwordEncoder = passwordEncoder;
        this.argon2Limiter = argon2Limiter;
        this.lockoutService = lockoutService;
        this.securityEventService = securityEventService;
        this.abuseThrottleService = abuseThrottleService;
    }

    public void verifyCurrentPassword(User user,
                                      String currentPassword,
                                      SecurityEventType eventType,
                                      String failureReason) {
        verifyCurrentPassword(user, currentPassword, eventType, SecurityEventSeverity.HIGH, failureReason);
    }

    public void verifyCurrentPassword(User user,
                                      String currentPassword,
                                      SecurityEventType eventType,
                                      SecurityEventSeverity failureSeverity,
                                      String failureReason) {
        requireNotLocked(user, eventType, failureReason);
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.STEP_UP_PASSWORD_USER, user);

        if (currentPassword == null || currentPassword.isBlank()) {
            recordFailedStepUp(user, eventType, failureSeverity, failureReason);
            throw new InvalidCredentialsException();
        }

        boolean acquired = argon2Limiter.tryAcquire();
        if (!acquired) {
            throw new AuthenticationCapacityExceededException();
        }

        try {
            if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
                recordFailedStepUp(user, eventType, failureSeverity, failureReason);
                throw new InvalidCredentialsException();
            }
        } finally {
            argon2Limiter.release();
        }
    }

    public void recordFailedStepUp(User user,
                                   SecurityEventType eventType,
                                   SecurityEventSeverity failureSeverity,
                                   String failureReason) {
        lockoutService.recordFailedAttempt(user.getEmail());
        securityEventService.recordForAuthenticatedUser(
                eventType,
                SecurityEventOutcome.DENIED,
                failureSeverity,
                user,
                failureReason);
        if (lockoutService.isLocked(user.getEmail())) {
            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.ACCOUNT_LOCKED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    failureReason + "_lockout_threshold_reached");
        }
    }

    public void requireNotLocked(User user, SecurityEventType eventType, String failureReason) {
        if (lockoutService.isLocked(user.getEmail())) {
            securityEventService.recordForAuthenticatedUser(
                    eventType,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    failureReason + "_account_locked");
            throw new AccountLockedException();
        }
    }

    public void checkMfaStepUp(User user) {
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.STEP_UP_MFA_USER, user);
    }
}
