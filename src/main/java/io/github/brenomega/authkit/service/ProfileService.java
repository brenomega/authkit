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
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import org.springframework.security.crypto.password.PasswordEncoder;
import io.github.brenomega.authkit.domain.user.dto.PasswordChangeRequest;
import io.github.brenomega.authkit.domain.user.dto.ProfileResponse;
import io.github.brenomega.authkit.domain.user.dto.SessionResponse;
import io.github.brenomega.authkit.exception.AuthenticationCapacityExceededException;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Service for user profile and session management (RF 2.1.6, RF 2.1.7, RF 2.1.8).
 *
 * <p>Provides operations for viewing and updating user profiles, changing
 * passwords, and managing active authentication sessions.</p>
 *
 * <h3>Security Hardening</h3>
 * <ul>
 *   <li><strong>IDOR Protection (DT 3.2.24):</strong> Profile updates enforce
 *       strict horizontal ID boundary checks, returning 404 for mismatched IDs.</li>
 *   <li><strong>Lockout Enforcement (DT 3.2.23):</strong> Password changes and
 *       session revocations are blocked when the account is locked.</li>
 *   <li><strong>Session Revocation (RF 2.1.12):</strong> Password changes trigger
 *       automatic revocation of all other active refresh tokens.</li>
 * </ul>
 *
 * @see AccountLockoutService
 * @see TokenStorage
 */
@Service
public class ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenStorage tokenStorage;
    private final AccountLockoutService lockoutService;
    private final Argon2ConcurrencyLimiter argon2Limiter;

    public ProfileService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                          TokenStorage tokenStorage, AccountLockoutService lockoutService,
                          Argon2ConcurrencyLimiter argon2Limiter) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenStorage = tokenStorage;
        this.lockoutService = lockoutService;
        this.argon2Limiter = argon2Limiter;
    }

    /**
     * Retrieves the profile information for the authenticated user (RF 2.1.6).
     *
     * @param userId the authenticated user's ID from the JWT subject
     * @return the user's profile data
     * @throws UserNotFoundException if the user does not exist
     */
    @LogExecutionTime
    public ProfileResponse getProfile(String userId) {
        @SuppressWarnings("null")
        User user = userRepository.findById(java.util.UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);
        requireTenantAccess(user);
        return new ProfileResponse(user.getId().toString(), user.getEmail(), user.getName(), user.getPhone());
    }

    /**
     * Updates profile info, enforcing that callers can only modify strictly their own data (RF 2.1.6).
     *
     * <p>A generic 404 is thrown for ID mismatches to halt enumeration (DT 3.2.24).</p>
     *
     * @param targetUserId        the ID provided in the URI
     * @param request             the validated properties to update
     * @param authenticatedUserId the Subject extracted from the Token context
     * @return the updated profile response
     * @throws UserNotFoundException if IDs do not match or user does not exist
     */
    @SuppressWarnings("null")
    @Transactional
    @LogExecutionTime
    public ProfileResponse updateProfile(String targetUserId, ProfileUpdateRequest request, String authenticatedUserId) {
        // Enforce strict horizontal ID level authorization boundary to prevent insecure direct object reference (IDOR).
        // A generic 404 is thrown to halt enumeration attempts (DT 3.2.24).
        if (!targetUserId.equals(authenticatedUserId)) {
            throw new UserNotFoundException();
        }

        @SuppressWarnings("null")
        User user = userRepository.findById(java.util.UUID.fromString(targetUserId))
                .orElseThrow(UserNotFoundException::new);

        requireTenantAccess(user);
        user.requireEmailConfirmed();

        // Update conditionally
        if (request.name() != null) {
            user.setName(request.name());
        }
        if (request.phone() != null) {
            user.setPhone(request.phone());
        }

        userRepository.save(user);
        return new ProfileResponse(user.getId().toString(), user.getEmail(), user.getName(), user.getPhone());
    }

    /**
     * Changes the password for an authenticated user after verifying current credentials (RF 2.1.7).
     *
     * <p><strong>Lockout Guard (DT 3.2.23):</strong> If the account is locked due to
     * progressive lockout, this operation is <strong>blocked</strong> even with a valid JWT.</p>
     *
     * <p>Upon success, all other active sessions are revoked for security hardening (RF 2.1.12).</p>
     *
     * @param userId     the authenticated user's ID
     * @param request    the password change payload with current and new passwords
     * @param currentJti the JTI of the current session (preserved during revocation)
     * @throws AccountLockedException    if the account is locked
     * @throws InvalidCredentialsException if the current password is invalid
     */
    @Transactional
    @LogExecutionTime
    public void changePassword(String userId, PasswordChangeRequest request, String currentJti) {
        @SuppressWarnings("null")
        User user = userRepository.findById(java.util.UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);

        requireTenantAccess(user);

        // DT 3.2.23: Block management operations while account is locked
        if (lockoutService.isLocked(user.getEmail())) {
            throw new AccountLockedException();
        }

        user.requireEmailConfirmed();

        // Security Check: Must verify current password before allowing change (RF 2.1.7)
        if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
            throw new InvalidCredentialsException();
        }

        // Hashing: Apply Argon2id with semaphore protection (DT 3.2.26)
        boolean acquired = argon2Limiter.tryAcquire();
        if (!acquired) {
            throw new AuthenticationCapacityExceededException();
        }

        try {
            user.setPassword(passwordEncoder.encode(request.newPassword()));
            userRepository.save(user);
        } finally {
            argon2Limiter.release();
        }

        // Session Revocation: Revoke all other active Refresh Tokens except current session (RF 2.1.12)
        tokenStorage.revokeOtherSessions(userId, currentJti);
    }

    /**
     * Lists active refresh token sessions for the user (RF 2.1.8, RF 2.1.10).
     *
     * @param userId the authenticated user's ID
     * @return a list of active session identifiers (JTIs)
     */
    public List<SessionResponse> listSessions(String userId) {
        @SuppressWarnings("null")
        User user = userRepository.findById(java.util.UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);
        requireTenantAccess(user);

        return tokenStorage.listSessions(userId).stream()
                .map(SessionResponse::new)
                .toList();
    }

    /**
     * Revokes a specific session by its JTI (RF 2.1.8).
     *
     * <p><strong>Lockout Guard (DT 3.2.23):</strong> Blocked while the account is locked.</p>
     *
     * @param userId the authenticated user's ID
     * @param jti    the JTI of the session to revoke
     * @throws AccountLockedException if the account is locked
     */
    public void revokeSession(String userId, String jti) {
        @SuppressWarnings("null")
        User user = userRepository.findById(java.util.UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);

        requireTenantAccess(user);

        // DT 3.2.23: Block session management while account is locked
        if (lockoutService.isLocked(user.getEmail())) {
            throw new AccountLockedException();
        }

        tokenStorage.revokeSession(userId, jti);
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
