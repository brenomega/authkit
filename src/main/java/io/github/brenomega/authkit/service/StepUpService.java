package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.Optional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.beans.factory.annotation.Autowired;
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
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

/**
 * Enforces recent proof of control before high-risk authenticated operations.
 *
 * <p>Password verification shares the global Argon2 concurrency limiter and the
 * progressive account lockout state used by login. Passwordless accounts may
 * satisfy the password portion only with a WebAuthn-authenticated JWT whose age
 * is within the configured freshness window. MFA verification itself remains a
 * collaborator responsibility.</p>
 */
@Service
public class StepUpService {

    private final PasswordEncoder passwordEncoder;
    private final Argon2ConcurrencyLimiter argon2Limiter;
    private final AccountLockoutService lockoutService;
    private final SecurityEventService securityEventService;
    private final AbuseThrottleService abuseThrottleService;
    private final AuthProperties authProperties;

    @Autowired
    public StepUpService(PasswordEncoder passwordEncoder,
                         Argon2ConcurrencyLimiter argon2Limiter,
                         AccountLockoutService lockoutService,
                         SecurityEventService securityEventService,
                         AbuseThrottleService abuseThrottleService,
                         AuthProperties authProperties) {
        this.passwordEncoder = passwordEncoder;
        this.argon2Limiter = argon2Limiter;
        this.lockoutService = lockoutService;
        this.securityEventService = securityEventService;
        this.abuseThrottleService = abuseThrottleService;
        this.authProperties = authProperties;
    }

    public StepUpService(PasswordEncoder passwordEncoder,
                         Argon2ConcurrencyLimiter argon2Limiter,
                         AccountLockoutService lockoutService,
                         SecurityEventService securityEventService,
                         AbuseThrottleService abuseThrottleService) {
        this(passwordEncoder, argon2Limiter, lockoutService, securityEventService, abuseThrottleService,
                new AuthProperties());
    }

    /**
     * Verifies password or a fresh local passkey and records failure against
     * lockout state using high audit severity.
     */
    public void verifyCurrentPassword(User user,
                                      String currentPassword,
                                      SecurityEventType eventType,
                                      String failureReason) {
        verifyCurrentPassword(user, currentPassword, eventType, SecurityEventSeverity.HIGH, failureReason);
    }

    /**
     * Verifies password or a fresh local passkey with caller-selected audit severity.
     *
     * @throws AccountLockedException if progressive lockout is already active
     * @throws AuthenticationCapacityExceededException if Argon2 capacity is exhausted
     * @throws InvalidCredentialsException if no accepted proof is present
     */
    public void verifyCurrentPassword(User user,
                                      String currentPassword,
                                      SecurityEventType eventType,
                                      SecurityEventSeverity failureSeverity,
                                      String failureReason) {
        requireNotLocked(user, eventType, failureReason);
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.STEP_UP_PASSWORD_USER, user);

        if (user.getPassword() == null) {
            if (hasFreshLocalPasskey()) {
                return;
            }
            recordFailedStepUp(user, eventType, failureSeverity, failureReason);
            throw new InvalidCredentialsException();
        }

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

    private boolean hasFreshLocalPasskey() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) return false;
        return Optional.ofNullable(jwt.getClaimAsStringList("amr"))
                .filter(amr -> amr.contains("webauthn"))
                .flatMap(amr -> Optional.ofNullable(jwt.getIssuedAt()))
                .map(issuedAt -> issuedAt.isAfter(Instant.now().minusSeconds(
                        authProperties.getStepUp().getPasskeyFreshnessSeconds())))
                .orElse(false);
    }

    /** Records one failed step-up and emits the threshold lockout event when reached. */
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

    /** Rejects locked accounts before performing an expensive credential check. */
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

    /** Applies the dedicated abuse-control policy before an MFA step-up attempt. */
    public void checkMfaStepUp(User user) {
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.STEP_UP_MFA_USER, user);
    }
}
