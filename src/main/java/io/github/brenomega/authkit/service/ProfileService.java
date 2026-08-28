package io.github.brenomega.authkit.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import io.github.brenomega.authkit.domain.user.dto.ProfileUpdateRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.JwtTenantResolver;
import io.github.brenomega.authkit.exception.AccountLockedException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.infrastructure.aop.LogExecutionTime;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;
import io.github.brenomega.authkit.infrastructure.security.AbuseRateLimitPolicy;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import org.springframework.security.crypto.password.PasswordEncoder;
import io.github.brenomega.authkit.domain.user.dto.PasswordChangeRequest;
import io.github.brenomega.authkit.domain.user.dto.ProfileResponse;
import io.github.brenomega.authkit.domain.user.dto.SessionResponse;
import io.github.brenomega.authkit.domain.user.dto.SessionPageResponse;
import io.github.brenomega.authkit.exception.InvalidSessionCursorException;
import io.github.brenomega.authkit.exception.AuthenticationCapacityExceededException;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import java.util.List;
import java.util.UUID;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

@Service
public class ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenStorage tokenStorage;
    private final AccountLockoutService lockoutService;
    private final Argon2ConcurrencyLimiter argon2Limiter;
    private final SecurityEventService securityEventService;
    private final MfaService mfaService;
    private final StepUpService stepUpService;
    private final AbuseThrottleService abuseThrottleService;
    private final PasswordPolicyService passwordPolicyService;

    public ProfileService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                          TokenStorage tokenStorage, AccountLockoutService lockoutService,
                          Argon2ConcurrencyLimiter argon2Limiter,
                          SecurityEventService securityEventService,
                          MfaService mfaService,
                          StepUpService stepUpService,
                          AbuseThrottleService abuseThrottleService,
                          PasswordPolicyService passwordPolicyService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenStorage = tokenStorage;
        this.lockoutService = lockoutService;
        this.argon2Limiter = argon2Limiter;
        this.securityEventService = securityEventService;
        this.mfaService = mfaService;
        this.stepUpService = stepUpService;
        this.abuseThrottleService = abuseThrottleService;
        this.passwordPolicyService = passwordPolicyService;
    }

    @LogExecutionTime
    public ProfileResponse getProfile(String userId) {
        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);
        requireTenantAccess(user);
        requireActive(user);
        return new ProfileResponse(user.getId().toString(), user.getEmail(), user.getName());
    }

    @Transactional
    @LogExecutionTime
    public ProfileResponse updateProfile(
        String targetUserId,
        ProfileUpdateRequest request,
        String authenticatedUserId) {

        if (!targetUserId.equals(authenticatedUserId)) {
            throw new UserNotFoundException();
        }

        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(targetUserId))
                .orElseThrow(UserNotFoundException::new);

        requireTenantAccess(user);
        requireActive(user);
        user.requireEmailConfirmed();
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.PROFILE_WRITE_USER, user);

        if (request.name() != null) {
            user.setName(request.name());
        }
        userRepository.save(user);
        return new ProfileResponse(user.getId().toString(), user.getEmail(), user.getName());
    }

    @Transactional
    @LogExecutionTime
    public void changePassword(String userId, PasswordChangeRequest request, String currentJti) {
        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);

        requireTenantAccess(user);
        requireActive(user);
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.PROFILE_WRITE_USER, user);

        if (lockoutService.isLocked(user.getEmail())) {
            securityEventService.recordForAuthenticatedUser(
                    SecurityEventType.PASSWORD_CHANGED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    "password_change_account_locked");
            throw new AccountLockedException();
        }

        user.requireEmailConfirmed();

        stepUpService.verifyCurrentPassword(
                user,
                request.currentPassword(),
                SecurityEventType.PASSWORD_CHANGED,
                "password_change_current_password_invalid");
        mfaService.requireMfaIfEnabled(user, request.mfaCode(), "password_change");
        passwordPolicyService.validateForUser(user, request.newPassword());

        boolean acquired = argon2Limiter.tryAcquire();
        if (!acquired) {
            throw new AuthenticationCapacityExceededException();
        }

        try {

            passwordPolicyService.recordCurrentPassword(user);
            user.setPassword(passwordEncoder.encode(request.newPassword()));
            userRepository.save(user);
        } finally {
            argon2Limiter.release();
        }

        tokenStorage.revokeOtherSessions(userId, currentJti);
        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.PASSWORD_CHANGED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.HIGH,
                user,
                "password_changed");
    }

    public SessionPageResponse listSessions(String userId, String currentJti, int limit, String cursor) {
        if (limit < 1 || limit > 100) {
            throw new InvalidSessionCursorException();
        }
        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);
        requireTenantAccess(user);
        requireActive(user);
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.SESSION_LIST_USER, user);

        var page = tokenStorage.listSessions(userId, limit, cursor);
        List<SessionResponse> sessions = page.items().stream()
                .map(session -> SessionResponse.from(session, currentJti))
                .toList();
        return new SessionPageResponse(sessions, page.nextCursor());
    }

    public SessionPageResponse listSessions(String userId, int limit, String cursor) {
        return listSessions(userId, null, limit, cursor);
    }

    public void revokeSession(String userId, String publicSessionId, String mfaCode) {
        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);

        requireTenantAccess(user);
        requireActive(user);
        abuseThrottleService.checkUser(AbuseRateLimitPolicy.PROFILE_WRITE_USER, user);

        if (lockoutService.isLocked(user.getEmail())) {
            throw new AccountLockedException();
        }

        mfaService.requireMfaIfEnabled(user, mfaCode, "session_revocation");
        tokenStorage.revokeSession(userId, publicSessionId);
        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.LOGOUT,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "session_revoked");
    }

    public void revokeSession(String userId, String publicSessionId) {
        revokeSession(userId, publicSessionId, null);
    }

    private void requireActive(User user) {
        user.requireActive();
    }

    private void requireTenantAccess(User user) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt jwt)) {
            return;
        }

        String tenantId = JwtTenantResolver.extractTenantId(jwt);

        if (tenantId == null || !tenantId.equals(user.getTenantId().toString())) {
            throw new UserNotFoundException();
        }
    }
}
