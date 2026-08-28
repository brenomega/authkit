package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.UUID;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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
import io.github.brenomega.authkit.infrastructure.security.JwtTokenUse;

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

    public record LoginResult(LoginResponse response, String refreshToken) {}

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

        @SuppressWarnings("null")
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

        lockoutService.clearLockout(email);

        String jti = UUID.randomUUID().toString();
        IssuedRefreshToken refreshToken = RefreshTokenCodec.issue(user.getId().toString(), jti);
        tokenStorage.storeRefreshToken(
                user.getId().toString(),
                jti,
                refreshToken.rawToken(),
                authProperties.getToken().getRefreshTokenTtlDays(),
                sessionMetadataFactory.create(
                        jti, List.of("pwd"), authProperties.getToken().getRefreshTokenTtlDays())
        );

        securityEventService.recordForAuthenticatedUser(
                SecurityEventType.LOGIN_SUCCESS,
                SecurityEventOutcome.SUCCESS,
                SecurityEventSeverity.LOW,
                user,
                "login_success");

        return issueTokenPair(user, refreshToken, List.of("pwd"));
    }

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
                        jti, completedAmr,
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

        List<String> amr = mfaService.isMfaEnabled(user)
                ? List.of("pwd", "mfa")
                : List.of("pwd");
        return issueTokenPair(user, nextRefreshToken, amr);
    }

    @LogExecutionTime
    public void logoutAll(String userId) {
        logoutAll(userId, null);
    }

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
