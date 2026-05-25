package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.brenomega.authkit.domain.user.dto.LoginRequest;
import io.github.brenomega.authkit.domain.user.dto.LoginResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec.IssuedRefreshToken;
import io.github.brenomega.authkit.exception.AuthenticationCapacityExceededException;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.exception.InvalidRefreshTokenException;
import io.github.brenomega.authkit.exception.TokenFamilyCompromisedException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

import io.github.brenomega.authkit.infrastructure.aop.LogExecutionTime;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

/**
 * Core authentication service handling the login lifecycle (RF 2.1.2).
 *
 * <p>Integrates with {@link AccountLockoutService} for progressive lockout
 * enforcement (DT 3.2.23) and implements stealth responses (DT 3.2.15)
 * to prevent account enumeration.</p>
 *
 * <p>Uses a {@link Semaphore} to limit concurrent Argon2id hash computations,
 * protecting against thread exhaustion (DT 3.2.26).</p>
 *
 * @see AccountLockoutService
 * @see TokenStorage
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtEncoder jwtEncoder;
    private final TokenStorage tokenStorage;
    private final AccountLockoutService lockoutService;
    private final AuthProperties authProperties;
    private final Argon2ConcurrencyLimiter argon2Limiter;
    private final SecurityEventService securityEventService;
    private final String dummyPasswordHash;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       JwtEncoder jwtEncoder, TokenStorage tokenStorage,
                       AccountLockoutService lockoutService,
                       AuthProperties authProperties,
                       Argon2ConcurrencyLimiter argon2Limiter,
                       SecurityEventService securityEventService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtEncoder = jwtEncoder;
        this.tokenStorage = tokenStorage;
        this.lockoutService = lockoutService;
        this.authProperties = authProperties;
        this.argon2Limiter = argon2Limiter;
        this.securityEventService = securityEventService;
        this.dummyPasswordHash = passwordEncoder.encode("AuthKit dummy password for timing equalization");
    }

    /**
     * Reusable container holding both public and restricted tokens post login.
     */
    public record LoginResult(LoginResponse response, String refreshToken) {}

    /**
     * Executes the secure identity negotiation lifecycle (RF 2.1.2).
     *
     * <p>Lockout flow (DT 3.2.23): After 5 failed attempts, the account is locked
     * and all subsequent login attempts return the same generic credential failure
     * used for invalid credentials.</p>
     *
     * @param request the login credentials
     * @return a {@link LoginResult} containing the access and refresh tokens
     */
    @LogExecutionTime
    public LoginResult login(LoginRequest request) {
        String email = EmailNormalizer.normalize(request.email());
        
        // DT 3.2.15 & DT 3.2.23: return the same credential failure while locked.
        if (lockoutService.isLocked(email)) {
            log.warn("Login rejected because lockout is active for normalized email.");
            securityEventService.recordForEmail(
                    SecurityEventType.LOGIN_FAILURE,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.MEDIUM,
                    email,
                    "account_locked");
            securityEventService.recordForEmail(
                    SecurityEventType.ACCOUNT_LOCKED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    email,
                    "login_attempt_while_locked");
            throw new InvalidCredentialsException();
        }

        var userOptional = userRepository.findByEmail(email);
        if (userOptional.filter(User::isDeleted).isPresent()) {
            matchesWithCapacity(request.password(), dummyPasswordHash);
            securityEventService.recordForEmail(
                    SecurityEventType.LOGIN_FAILURE,
                    SecurityEventOutcome.FAILURE,
                    SecurityEventSeverity.MEDIUM,
                    email,
                    "deleted_account");
            throw new InvalidCredentialsException();
        }

        String hashToCheck = userOptional.map(User::getPassword).orElse(dummyPasswordHash);
                
        boolean passwordMatches = matchesWithCapacity(request.password(), hashToCheck);

        if (userOptional.isEmpty() || !passwordMatches) {
            if (userOptional.isPresent()) {
                lockoutService.recordFailedAttempt(email);
                securityEventService.recordForUser(
                        SecurityEventType.LOGIN_FAILURE,
                        SecurityEventOutcome.FAILURE,
                        SecurityEventSeverity.MEDIUM,
                        userOptional.get(),
                        "invalid_credentials");
                if (lockoutService.isLocked(email)) {
                    securityEventService.recordForUser(
                            SecurityEventType.ACCOUNT_LOCKED,
                            SecurityEventOutcome.DENIED,
                            SecurityEventSeverity.HIGH,
                            userOptional.get(),
                            "progressive_lockout_threshold_reached");
                }
            } else {
                securityEventService.recordForEmail(
                        SecurityEventType.LOGIN_FAILURE,
                        SecurityEventOutcome.FAILURE,
                        SecurityEventSeverity.MEDIUM,
                        email,
                        "unknown_account");
            }
            throw new InvalidCredentialsException();
        }

        User user = userOptional.get();
        if (!user.isEmailConfirmed()) {
            securityEventService.recordForUser(
                    SecurityEventType.LOGIN_FAILURE,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.MEDIUM,
                    user,
                    "email_not_confirmed");
        }
        user.requireEmailConfirmed();
        
        // Clear limits on legit sign in
        lockoutService.clearLockout(email);

        String jti = UUID.randomUUID().toString();
        IssuedRefreshToken refreshToken = RefreshTokenCodec.issue(user.getId().toString(), jti);
        tokenStorage.storeRefreshToken(
                user.getId().toString(),
                jti,
                refreshToken.rawToken(),
                authProperties.getToken().getRefreshTokenTtlDays()
        );

        securityEventService.recordForUser(
                SecurityEventType.LOGIN_SUCCESS,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.LOW,
                user,
                "login_success");

        return issueTokenPair(user, refreshToken);
    }

    /**
     * Rotates a refresh token and returns a new access/refresh token pair.
     */
    @LogExecutionTime
    public LoginResult refresh(String rawRefreshToken) {
        IssuedRefreshToken currentRefreshToken = RefreshTokenCodec.parse(rawRefreshToken)
                .orElseThrow(() -> {
                    securityEventService.record(
                            SecurityEventType.REFRESH_TOKEN_FAILED,
                            SecurityEventOutcome.FAILURE,
                            SecurityEventSeverity.MEDIUM,
                            null,
                            null,
                            null,
                            null,
                            "malformed_refresh_token",
                            java.util.Map.of());
                    return new InvalidRefreshTokenException();
                });

        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(currentRefreshToken.userId()))
                .orElseThrow(() -> {
                    UUID subject = UUID.fromString(currentRefreshToken.userId());
                    securityEventService.record(
                            SecurityEventType.REFRESH_TOKEN_FAILED,
                            SecurityEventOutcome.FAILURE,
                            SecurityEventSeverity.HIGH,
                            subject,
                            subject,
                            null,
                            null,
                            "refresh_user_not_found",
                            java.util.Map.of());
                    return new InvalidRefreshTokenException();
                });

        if (lockoutService.isLocked(user.getEmail())) {
            log.warn("Refresh rejected because lockout is active for normalized email.");
            securityEventService.recordForUser(
                    SecurityEventType.REFRESH_TOKEN_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    "account_locked");
            throw new InvalidRefreshTokenException();
        }
        if (!user.isEmailConfirmed() || user.isDeleted()) {
            securityEventService.recordForUser(
                    SecurityEventType.REFRESH_TOKEN_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    "inactive_account");
        }
        user.requireEmailConfirmed();

        String nextJti = UUID.randomUUID().toString();
        IssuedRefreshToken nextRefreshToken = RefreshTokenCodec.issueRotated(
                user.getId().toString(), nextJti, currentRefreshToken.familyId());

        boolean rotated;
        try {
            rotated = tokenStorage.rotateRefreshToken(
                    user.getId().toString(),
                    currentRefreshToken.jti(),
                    currentRefreshToken.rawToken(),
                    nextRefreshToken.jti(),
                    nextRefreshToken.rawToken(),
                    authProperties.getToken().getRefreshTokenTtlDays()
            );
        } catch (TokenFamilyCompromisedException ex) {
            securityEventService.recordForUser(
                    SecurityEventType.REFRESH_TOKEN_REUSE_DETECTED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.CRITICAL,
                    user,
                    "refresh_token_family_reuse_detected");
            throw ex;
        }

        if (!rotated) {
            securityEventService.recordForUser(
                    SecurityEventType.REFRESH_TOKEN_FAILED,
                    SecurityEventOutcome.FAILURE,
                    SecurityEventSeverity.HIGH,
                    user,
                    "refresh_rotation_failed");
            throw new InvalidRefreshTokenException();
        }

        securityEventService.recordForUser(
                SecurityEventType.REFRESH_TOKEN_ROTATED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.LOW,
                user,
                "refresh_token_rotated");

        return issueTokenPair(user, nextRefreshToken);
    }

    /**
     * Proactively revokes all active refresh token sessions for the given user (DT 3.2.11).
     */
    @LogExecutionTime
    public void logoutAll(String userId) {
        tokenStorage.revokeAllSessions(userId);
        UUID userUuid = UUID.fromString(userId);
        securityEventService.record(
                SecurityEventType.LOGOUT_ALL,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                userUuid,
                userUuid,
                null,
                null,
                "logout_all",
                java.util.Map.of());
    }

    /**
     * Revokes a refresh-token-backed session. Malformed or absent tokens are
     * treated as a client cleanup no-op so logout remains idempotent.
     */
    @LogExecutionTime
    public void logout(String rawRefreshToken) {
        RefreshTokenCodec.parse(rawRefreshToken)
                .ifPresent(token -> {
                    tokenStorage.revokeSession(token.userId(), token.jti());
                    UUID userUuid = UUID.fromString(token.userId());
                    securityEventService.record(
                            SecurityEventType.LOGOUT,
                            SecurityEventOutcome.SUCCESS,
                            SecurityEventSeverity.LOW,
                            userUuid,
                            userUuid,
                            null,
                            null,
                            "logout_current_session",
                            java.util.Map.of());
                });
    }

    private LoginResult issueTokenPair(User user, IssuedRefreshToken refreshToken) {
        Instant now = Instant.now();
        long accessTokenTtlSeconds = authProperties.getToken().getAccessTokenTtlSeconds();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(authProperties.getJwt().getIssuer())
                .audience(java.util.List.of(authProperties.getJwt().getAudience()))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(accessTokenTtlSeconds))
                .subject(user.getId().toString())
                .id(refreshToken.jti()) // DT 3.2.3: bind access token to refresh session JTI
                .claim("tenant_id", user.getTenantId().toString())
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        LoginResponse responseDto = new LoginResponse(accessToken, accessTokenTtlSeconds);
        return new LoginResult(responseDto, refreshToken.rawToken());
    }

    private boolean matchesWithCapacity(String rawPassword, String encodedPassword) {
        boolean acquired = argon2Limiter.tryAcquire();
        if (!acquired) {
            throw new AuthenticationCapacityExceededException();
        }

        try {
            return passwordEncoder.matches(rawPassword, encodedPassword);
        } finally {
            argon2Limiter.release();
        }
    }
}
