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
import io.github.brenomega.authkit.domain.mfa.dto.MfaLoginVerificationRequest;
import io.github.brenomega.authkit.domain.mfa.util.MfaChallengeCodec;
import io.github.brenomega.authkit.domain.mfa.util.MfaChallengeCodec.IssuedMfaChallenge;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec.IssuedRefreshToken;
import io.github.brenomega.authkit.exception.AuthenticationCapacityExceededException;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.exception.InvalidMfaCodeException;
import io.github.brenomega.authkit.exception.InvalidRefreshTokenException;
import io.github.brenomega.authkit.exception.TokenFamilyCompromisedException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

import io.github.brenomega.authkit.infrastructure.aop.LogExecutionTime;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventOutcome;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventSeverity;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventType;
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;
import io.github.brenomega.authkit.infrastructure.security.AbuseRateLimitPolicy;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

/**
 * Coordinates first-party authentication and refresh-session lifecycle.
 *
 * <p>Password login normalizes the identifier, applies abuse and progressive
 * lockout controls, and performs a dummy Argon2 verification for unknown users.
 * No refresh session is created until every required factor has succeeded.
 * Authentication failures intentionally do not disclose whether an account
 * exists, is locked, or has an invalid password.</p>
 *
 * <p>Issued first-party access tokens are bound by {@code jti} to a server-side
 * refresh session. Consequently, session revocation invalidates both refresh use
 * and subsequent access-token authorization through
 * {@link io.github.brenomega.authkit.infrastructure.security.UserAuthoritiesFilter}.</p>
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
    private final MfaService mfaService;
    private final AbuseThrottleService abuseThrottleService;
    private final SessionMetadataFactory sessionMetadataFactory;
    private final String dummyPasswordHash;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       JwtEncoder jwtEncoder, TokenStorage tokenStorage,
                       AccountLockoutService lockoutService,
                       AuthProperties authProperties,
                       Argon2ConcurrencyLimiter argon2Limiter,
                       SecurityEventService securityEventService,
                       MfaService mfaService,
                       AbuseThrottleService abuseThrottleService,
                       SessionMetadataFactory sessionMetadataFactory) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtEncoder = jwtEncoder;
        this.tokenStorage = tokenStorage;
        this.lockoutService = lockoutService;
        this.authProperties = authProperties;
        this.argon2Limiter = argon2Limiter;
        this.securityEventService = securityEventService;
        this.mfaService = mfaService;
        this.abuseThrottleService = abuseThrottleService;
        this.sessionMetadataFactory = sessionMetadataFactory;
        this.dummyPasswordHash = passwordEncoder.encode("AuthKit dummy password for timing equalization");
    }

    /**
     * Keeps the HTTP-safe response separate from the refresh secret that is
     * written only to a protected cookie.
     */
    public record LoginResult(LoginResponse response, String refreshToken) {}

    /**
     * Authenticates a password or starts the MFA continuation of that login.
     *
     * <p>An MFA continuation is a short-lived, single-use challenge rather than
     * an authenticated session. Lockout state is cleared only after the entire
     * ceremony succeeds.</p>
     *
     * @param request the login credentials
     * @return a token pair, or a response containing only an MFA challenge
     */
    @LogExecutionTime
    public LoginResult login(LoginRequest request) {
        String email = EmailNormalizer.normalize(request.email());
        abuseThrottleService.checkEmail(AbuseRateLimitPolicy.LOGIN_EMAIL, email);
        
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
                securityEventService.recordForTargetUser(
                        SecurityEventType.LOGIN_FAILURE,
                        SecurityEventOutcome.FAILURE,
                        SecurityEventSeverity.MEDIUM,
                        userOptional.get(),
                        "invalid_credentials");
                if (lockoutService.isLocked(email)) {
                    securityEventService.recordForTargetUser(
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
            securityEventService.recordForTargetUser(
                    SecurityEventType.LOGIN_FAILURE,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.MEDIUM,
                    user,
                    "email_not_confirmed");
        }
        user.requireEmailConfirmed();
        
        if (mfaService.isMfaEnabled(user)) {
            IssuedMfaChallenge mfaChallenge = MfaChallengeCodec.issue(user.getId().toString());
            tokenStorage.storeMfaChallenge(
                    user.getId().toString(),
                    mfaChallenge.jti(),
                    mfaChallenge.rawToken(),
                    authProperties.getMfa().getLoginChallengeTtlMinutes());
            securityEventService.recordForTargetUser(
                    SecurityEventType.MFA_CHALLENGE_ISSUED,
                    SecurityEventOutcome.INFO,
                    SecurityEventSeverity.MEDIUM,
                    user,
                    "login_mfa_challenge_issued");
            return new LoginResult(LoginResponse.mfaRequired(mfaChallenge.rawToken()), null);
        }

        // Clear limits only after the full authentication ceremony has completed.
        lockoutService.clearLockout(email);

        String jti = UUID.randomUUID().toString();
        IssuedRefreshToken refreshToken = RefreshTokenCodec.issue(user.getId().toString(), jti);
        tokenStorage.storeRefreshToken(
                user.getId().toString(),
                jti,
                refreshToken.rawToken(),
                authProperties.getToken().getRefreshTokenTtlDays(),
                sessionMetadataFactory.create(
                        jti, java.util.List.of("pwd"), authProperties.getToken().getRefreshTokenTtlDays())
        );

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.LOGIN_SUCCESS,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.LOW,
                user,
                "login_success");

        return issueTokenPair(user, refreshToken, java.util.List.of("pwd"));
    }

    /**
     * Completes a pending password login with TOTP or a backup code.
     *
     * <p>The login challenge is consumed before the factor is verified and cannot
     * be replayed after either success or failure. A successful backup code is
     * also consumed exactly once by {@link MfaService}.</p>
     */
    @LogExecutionTime
    public LoginResult verifyMfaLogin(MfaLoginVerificationRequest request) {
        IssuedMfaChallenge challenge = MfaChallengeCodec.parse(request.mfaToken())
                .orElseThrow(() -> {
                    securityEventService.record(
                            SecurityEventType.MFA_CHALLENGE_FAILED,
                            SecurityEventOutcome.FAILURE,
                            SecurityEventSeverity.HIGH,
                            null,
                            null,
                            null,
                            null,
                            "malformed_mfa_challenge",
                            java.util.Map.of());
                    return new InvalidMfaCodeException();
                });

        UUID userId = UUID.fromString(challenge.userId());
        abuseThrottleService.checkUserId(AbuseRateLimitPolicy.MFA_VERIFY_USER, userId);
        @SuppressWarnings("null")
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    securityEventService.record(
                            SecurityEventType.MFA_CHALLENGE_FAILED,
                            SecurityEventOutcome.FAILURE,
                            SecurityEventSeverity.HIGH,
                            userId,
                            userId,
                            null,
                            null,
                            "mfa_challenge_user_not_found",
                            java.util.Map.of());
                    return new InvalidMfaCodeException();
                });

        if (lockoutService.isLocked(user.getEmail())) {
            securityEventService.recordForTargetUser(
                    SecurityEventType.MFA_CHALLENGE_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    "mfa_challenge_account_locked");
            throw new InvalidMfaCodeException();
        }

        if (!tokenStorage.consumeMfaChallenge(challenge.userId(), challenge.jti(), challenge.rawToken())) {
            securityEventService.recordForTargetUser(
                    SecurityEventType.MFA_CHALLENGE_FAILED,
                    SecurityEventOutcome.FAILURE,
                    SecurityEventSeverity.HIGH,
                    user,
                    "mfa_challenge_invalid_or_expired");
            throw new InvalidMfaCodeException();
        }

        if (!user.isEmailConfirmed() || !user.isActive()) {
            securityEventService.recordForTargetUser(
                    SecurityEventType.MFA_CHALLENGE_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    "mfa_challenge_inactive_account");
            throw new InvalidMfaCodeException();
        }

        var mfaResult = mfaService.verifyMfaCode(user, request.code(), "login_mfa");
        if (!mfaResult.valid()) {
            lockoutService.recordFailedAttempt(user.getEmail());
            securityEventService.recordForTargetUser(
                    SecurityEventType.MFA_CHALLENGE_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    "login_mfa_invalid_code");
            if (lockoutService.isLocked(user.getEmail())) {
                securityEventService.recordForTargetUser(
                        SecurityEventType.ACCOUNT_LOCKED,
                        SecurityEventOutcome.DENIED,
                        SecurityEventSeverity.HIGH,
                        user,
                        "mfa_failure_lockout_threshold_reached");
            }
            throw new InvalidMfaCodeException();
        }

        lockoutService.clearLockout(user.getEmail());

        java.util.List<String> completedAmr = new java.util.ArrayList<>(challenge.initialAmr());
        completedAmr.add(mfaResult.method());
        completedAmr = completedAmr.stream().distinct().toList();
        String jti = UUID.randomUUID().toString();
        IssuedRefreshToken refreshToken = RefreshTokenCodec.issue(user.getId().toString(), jti);
        tokenStorage.storeRefreshToken(
                user.getId().toString(),
                jti,
                refreshToken.rawToken(),
                authProperties.getToken().getRefreshTokenTtlDays(),
                sessionMetadataFactory.create(
                        jti, completedAmr,
                        authProperties.getToken().getRefreshTokenTtlDays())
        );

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.MFA_CHALLENGE_VERIFIED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "login_mfa_verified",
                java.util.Map.of("method", mfaResult.method()));
        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.LOGIN_SUCCESS,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.LOW,
                user,
                "login_success_mfa");

        return issueTokenPair(user, refreshToken, completedAmr);
    }

    /**
     * Rotates a refresh token and returns its successor token pair.
     *
     * <p>Rotation is delegated to {@link TokenStorage} as an atomic family
     * transition. Replay of an already rotated token revokes the active family
     * member and is reported as a compromised family.</p>
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
            securityEventService.recordForTargetUser(
                    SecurityEventType.REFRESH_TOKEN_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    "account_locked");
            throw new InvalidRefreshTokenException();
        }
        if (!user.isActive()) {
            securityEventService.recordForTargetUser(
                    SecurityEventType.REFRESH_TOKEN_FAILED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.HIGH,
                    user,
                    "inactive_account");
            throw new InvalidRefreshTokenException();
        }
        if (!user.isEmailConfirmed()) {
            securityEventService.recordForTargetUser(
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
            securityEventService.recordForTargetUser(
                    SecurityEventType.REFRESH_TOKEN_REUSE_DETECTED,
                    SecurityEventOutcome.DENIED,
                    SecurityEventSeverity.CRITICAL,
                    user,
                    "refresh_token_family_reuse_detected");
            throw ex;
        }

        if (!rotated) {
            securityEventService.recordForTargetUser(
                    SecurityEventType.REFRESH_TOKEN_FAILED,
                    SecurityEventOutcome.FAILURE,
                    SecurityEventSeverity.HIGH,
                    user,
                    "refresh_rotation_failed");
            throw new InvalidRefreshTokenException();
        }

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.REFRESH_TOKEN_ROTATED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.LOW,
                user,
                "refresh_token_rotated");

        java.util.List<String> amr = mfaService.isMfaEnabled(user)
                ? java.util.List.of("pwd", "mfa")
                : java.util.List.of("pwd");
        return issueTokenPair(user, nextRefreshToken, amr);
    }

    /**
     * Revokes all refresh sessions after any configured MFA step-up.
     */
    @LogExecutionTime
    public void logoutAll(String userId) {
        logoutAll(userId, null);
    }

    /**
     * Revokes all refresh sessions, requiring an MFA code when the user has MFA enabled.
     */
    @LogExecutionTime
    public void logoutAll(String userId, String mfaCode) {
        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(UserNotFoundException::new);
        if (!user.isActive()) {
            throw new UserNotFoundException();
        }

        mfaService.requireMfaIfEnabled(user, mfaCode, "logout_all");
        tokenStorage.revokeAllSessions(userId);
        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.LOGOUT_ALL,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "logout_all");
    }

    /**
     * Revokes a refresh-token-backed session.
     *
     * <p>Malformed, expired, absent, or already revoked tokens are cleanup no-ops,
     * making logout idempotent from the caller's perspective.</p>
     */
    @LogExecutionTime
    public void logout(String rawRefreshToken) {
        RefreshTokenCodec.parse(rawRefreshToken)
                .filter(token -> tokenStorage.validateToken(token.userId(), token.jti(), token.rawToken()))
                .ifPresent(token -> {
                    tokenStorage.revokeSessionByJti(token.userId(), token.jti());
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

    /**
     * Issues a first-party session for a user already verified by a non-password ceremony.
     *
     * <p>Callers are responsible for the ceremony's cryptographic verification;
     * this method still enforces account activity and email confirmation before
     * creating the session.</p>
     *
     * @param amr authentication-method references to preserve in the JWT
     * @param reason stable audit reason for the successful login
     */
    public LoginResult issueLoginForVerifiedUser(User user, java.util.List<String> amr, String reason) {
        if (!user.isActive()) {
            throw new InvalidCredentialsException();
        }
        user.requireEmailConfirmed();
        lockoutService.clearLockout(user.getEmail());

        String jti = UUID.randomUUID().toString();
        IssuedRefreshToken refreshToken = RefreshTokenCodec.issue(user.getId().toString(), jti);
        tokenStorage.storeRefreshToken(
                user.getId().toString(),
                jti,
                refreshToken.rawToken(),
                authProperties.getToken().getRefreshTokenTtlDays(),
                sessionMetadataFactory.create(
                        jti, amr, authProperties.getToken().getRefreshTokenTtlDays())
        );

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.LOGIN_SUCCESS,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.LOW,
                user,
                reason);

        return issueTokenPair(user, refreshToken, amr);
    }

    public LoginResult beginFederatedLogin(User user, String providerKey) {
        java.util.List<String> amr = java.util.List.of("federated", "oidc:" + providerKey);
        if (!mfaService.isMfaEnabled(user)) {
            return issueLoginForVerifiedUser(user, amr, "login_success_social");
        }
        IssuedMfaChallenge challenge = MfaChallengeCodec.issue(user.getId().toString(), amr);
        tokenStorage.storeMfaChallenge(user.getId().toString(), challenge.jti(), challenge.rawToken(),
                authProperties.getMfa().getLoginChallengeTtlMinutes());
        securityEventService.recordForTargetUser(
                SecurityEventType.MFA_CHALLENGE_ISSUED,
                SecurityEventOutcome.INFO,
                SecurityEventSeverity.MEDIUM,
                user,
                "social_login_local_mfa_challenge_issued");
        return new LoginResult(LoginResponse.mfaRequired(challenge.rawToken()), null);
    }

    private LoginResult issueTokenPair(User user, IssuedRefreshToken refreshToken, java.util.List<String> amr) {
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
                .claim(io.github.brenomega.authkit.infrastructure.security.JwtTokenUse.CLAIM,
                        io.github.brenomega.authkit.infrastructure.security.JwtTokenUse.FIRST_PARTY_ACCESS)
                .claim("amr", amr)
                .claim("mfa", amr.stream().anyMatch(method -> !"pwd".equals(method)))
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
