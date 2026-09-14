package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.UUID;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
import io.github.brenomega.authkit.exception.ConsentRequiredException;
import io.github.brenomega.authkit.exception.TokenFamilyCompromisedException;
import io.github.brenomega.authkit.exception.UserNotFoundException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import io.github.brenomega.authkit.service.spi.SessionMetadata;

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
import io.github.brenomega.authkit.infrastructure.security.JwtTokenUse;

/**
 * Coordinates first-party authentication and revocable session issuance.
 *
 * <p>Password login normalizes identifiers, applies abuse and progressive
 * lockout controls, and performs a dummy Argon2 verification for unknown or
 * deleted accounts. No refresh session is created until every required factor
 * succeeds. Authentication failures deliberately collapse account existence,
 * lockout and credential state into common public errors.</p>
 *
 * <p>Each access token shares its {@code jti} with a server-side refresh session.
 * Consequently, revoking that session also invalidates access-token use through
 * {@link io.github.brenomega.authkit.infrastructure.security.UserAuthoritiesFilter}.</p>
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

    /** Separates the public response from the refresh secret handled by the controller cookie boundary. */
    public record LoginResult(LoginResponse response, String refreshToken) {}

    /**
     * Performs password authentication and either creates a session or issues an
     * intermediate MFA challenge.
     *
     * <p>The challenge is not a session and carries no access authority. Argon2
     * capacity exhaustion is surfaced rather than queued without bound.</p>
     */
@SuppressWarnings("null")
@LogExecutionTime
    public LoginResult login(LoginRequest request) {
        String email = EmailNormalizer.normalize(request.email());
        abuseThrottleService.checkEmail(AbuseRateLimitPolicy.LOGIN_EMAIL, email);

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

        boolean hasRealPassword = userOptional
                .map(user -> user.getPassword() != null)
                .orElse(false);
        String hashToCheck = hasRealPassword
                ? userOptional.orElseThrow().getPassword()
                : dummyPasswordHash;

        boolean passwordMatches = matchesWithCapacity(request.password(), hashToCheck);

        // The dummy hash equalizes password work only. It must never become an
        // authentication credential for an unknown or passwordless account.
        if (userOptional.isEmpty() || !hasRealPassword || !passwordMatches) {
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

        lockoutService.clearLockout(email);

        String jti = UUID.randomUUID().toString();
        IssuedRefreshToken refreshToken = RefreshTokenCodec.issue(user.getId().toString(), jti);
        tokenStorage.storeRefreshToken(
                user.getId().toString(),
                jti,
                refreshToken.rawToken(),
                authProperties.getToken().getRefreshTokenTtlDays(),
                sessionMetadataFactory.create(
                        jti, user.getSecurityVersion(), List.of("pwd"),
                        authProperties.getToken().getRefreshTokenTtlDays())
        );

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.LOGIN_SUCCESS,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.LOW,
                user,
                "login_success");

        return issueTokenPair(user, refreshToken, List.of("pwd"));
    }

    /**
     * Completes a password or federated login after local MFA.
     *
     * <p>The login challenge is consumed before the MFA code is evaluated, so a
     * failed code cannot be retried with the same challenge. Lockout is cleared
     * and session state is created only after successful verification.</p>
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
                            Map.of());
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
                            Map.of());
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

        List<String> completedAmr = new ArrayList<>(challenge.initialAmr());
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
                        jti, user.getSecurityVersion(), completedAmr,
                        authProperties.getToken().getRefreshTokenTtlDays())
        );

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.MFA_CHALLENGE_VERIFIED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.MEDIUM,
                user,
                "login_mfa_verified",
                Map.of("method", mfaResult.method()));
        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.LOGIN_SUCCESS,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.LOW,
                user,
                "login_success_mfa");

        return issueTokenPair(user, refreshToken, completedAmr);
    }

    /**
     * Rotates a refresh secret and returns a new access/refresh pair.
     *
     * <p>Atomic rotation and replay detection are delegated to
     * {@link TokenStorage}. Reuse of an advanced family revokes its active member
     * and is audited as a critical compromise event.</p>
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
                            Map.of());
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
                            Map.of());
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

        requireCurrentConsent(user);

        Optional<SessionMetadata> currentMetadata = tokenStorage
                .findSessionMetadata(user.getId().toString(), currentRefreshToken.jti());
        if (currentMetadata.isPresent() && !user.acceptsSession(
                currentRefreshToken.jti(), currentMetadata.get().securityVersion())) {
            throw new InvalidRefreshTokenException();
        }

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
                    authProperties.getToken().getRefreshTokenTtlDays(),
                    user.getSecurityVersion()
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

        List<String> preservedAmr = currentMetadata
                .map(SessionMetadata::initialAmr)
                .orElseThrow(InvalidRefreshTokenException::new);
        if (preservedAmr.isEmpty()) {
            throw new InvalidRefreshTokenException();
        }

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.REFRESH_TOKEN_ROTATED,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.LOW,
                user,
                "refresh_token_rotated");

        return issueTokenPair(user, nextRefreshToken, preservedAmr);
    }

    /** Revokes all sessions, requiring MFA when configured for the account. */
    @LogExecutionTime
    public void logoutAll(String userId) {
        logoutAll(userId, null);
    }

    /** Revokes all sessions after applying the account's current MFA policy. */
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
     * Revokes the session identified by a refresh secret.
     *
     * <p>Malformed, expired and already revoked values are cleanup no-ops, making
     * logout idempotent from the caller's perspective.</p>
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
                            Map.of());
                });
    }

    /**
     * Creates a first-party session for an identity already verified by a trusted ceremony.
     *
     * @param amr authentication methods completed by that ceremony
     * @param reason stable audit reason for successful login
     */
    public LoginResult issueLoginForVerifiedUser(User user, List<String> amr, String reason) {
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
                        jti, user.getSecurityVersion(), amr,
                        authProperties.getToken().getRefreshTokenTtlDays())
        );

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.LOGIN_SUCCESS,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.LOW,
                user,
                reason);

        return issueTokenPair(user, refreshToken, amr);
    }

    /**
     * Continues a verified social login through local MFA when the account requires it.
     *
     * <p>The provider key is recorded in {@code amr}; it is not treated as a local
     * MFA factor.</p>
     */
    public LoginResult beginFederatedLogin(User user, String providerKey) {
        List<String> amr = List.of("federated", "oidc:" + providerKey);
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

    private LoginResult issueTokenPair(User user, IssuedRefreshToken refreshToken, List<String> amr) {
        Instant now = Instant.now();
        long accessTokenTtlSeconds = authProperties.getToken().getAccessTokenTtlSeconds();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(authProperties.getJwt().getIssuer())
                .audience(List.of(authProperties.getJwt().getAudience()))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(accessTokenTtlSeconds))
                .subject(user.getId().toString())
                .id(refreshToken.jti())
                .claim("tenant_id", user.getTenantId().toString())
                .claim(JwtTokenUse.CLAIM,
                        JwtTokenUse.FIRST_PARTY_ACCESS)
                .claim("amr", amr)
                .claim("mfa", amr.stream().anyMatch(method ->
                        "otp".equals(method) || "backup_code".equals(method)))
                .claim("consent_required", !hasCurrentConsent(user))
                .claim("session_version", user.getSecurityVersion())
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        LoginResponse responseDto = new LoginResponse(accessToken, accessTokenTtlSeconds);
        return new LoginResult(responseDto, refreshToken.rawToken());
    }

    private void requireCurrentConsent(User user) {
        if (!hasCurrentConsent(user)) {
            throw new ConsentRequiredException();
        }
    }

    private boolean hasCurrentConsent(User user) {
        return user.hasCurrentConsent(authProperties.getCompliance().getTermsVersion(),
                authProperties.getCompliance().getPrivacyPolicyVersion());
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
