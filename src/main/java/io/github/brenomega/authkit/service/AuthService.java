package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.util.concurrent.Semaphore;

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
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

import io.github.brenomega.authkit.infrastructure.aop.LogExecutionTime;
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;

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
    private static final long ACCESS_TOKEN_TTL_SECONDS = 900;
    private static final long REFRESH_TOKEN_TTL_DAYS = 7;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtEncoder jwtEncoder;
    private final TokenStorage tokenStorage;
    private final AccountLockoutService lockoutService;
    private final String dummyPasswordHash;

    // Concurrency Limit (N = cores * 1.5) to brutally protect against Thread Exhaustion
    private final Semaphore argon2Semaphore;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       JwtEncoder jwtEncoder, TokenStorage tokenStorage,
                       AccountLockoutService lockoutService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtEncoder = jwtEncoder;
        this.tokenStorage = tokenStorage;
        this.lockoutService = lockoutService;
        this.dummyPasswordHash = passwordEncoder.encode("AuthKit dummy password for timing equalization");
        
        int permits = (int) (Runtime.getRuntime().availableProcessors() * 1.5);
        this.argon2Semaphore = new Semaphore(Math.max(2, permits)); 
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
            throw new InvalidCredentialsException();
        }

        var userOptional = userRepository.findByEmail(email);
        String hashToCheck = userOptional.map(User::getPassword).orElse(dummyPasswordHash);
                
        boolean passwordMatches = matchesWithCapacity(request.password(), hashToCheck);

        if (userOptional.isEmpty() || !passwordMatches) {
            if (userOptional.isPresent()) {
                lockoutService.recordFailedAttempt(email);
            }
            throw new InvalidCredentialsException();
        }

        User user = userOptional.get();
        
        // Clear limits on legit sign in
        lockoutService.clearLockout(email);

        String jti = UUID.randomUUID().toString();
        IssuedRefreshToken refreshToken = RefreshTokenCodec.issue(user.getId().toString(), jti);
        tokenStorage.storeRefreshToken(
                user.getId().toString(),
                jti,
                refreshToken.rawToken(),
                REFRESH_TOKEN_TTL_DAYS
        );

        return issueTokenPair(user, refreshToken);
    }

    /**
     * Rotates a refresh token and returns a new access/refresh token pair.
     */
    @LogExecutionTime
    public LoginResult refresh(String rawRefreshToken) {
        IssuedRefreshToken currentRefreshToken = RefreshTokenCodec.parse(rawRefreshToken)
                .orElseThrow(InvalidRefreshTokenException::new);

        @SuppressWarnings("null")
        User user = userRepository.findById(UUID.fromString(currentRefreshToken.userId()))
                .orElseThrow(InvalidRefreshTokenException::new);

        if (lockoutService.isLocked(user.getEmail())) {
            log.warn("Refresh rejected because lockout is active for normalized email.");
            throw new InvalidRefreshTokenException();
        }

        String nextJti = UUID.randomUUID().toString();
        IssuedRefreshToken nextRefreshToken = RefreshTokenCodec.issue(user.getId().toString(), nextJti);

        boolean rotated = tokenStorage.rotateRefreshToken(
                user.getId().toString(),
                currentRefreshToken.jti(),
                currentRefreshToken.rawToken(),
                nextRefreshToken.jti(),
                nextRefreshToken.rawToken(),
                REFRESH_TOKEN_TTL_DAYS
        );

        if (!rotated) {
            throw new InvalidRefreshTokenException();
        }

        return issueTokenPair(user, nextRefreshToken);
    }

    /**
     * Revokes a refresh-token-backed session. Malformed or absent tokens are
     * treated as a client cleanup no-op so logout remains idempotent.
     */
    @LogExecutionTime
    public void logout(String rawRefreshToken) {
        RefreshTokenCodec.parse(rawRefreshToken)
                .ifPresent(token -> tokenStorage.revokeSession(token.userId(), token.jti()));
    }

    private LoginResult issueTokenPair(User user, IssuedRefreshToken refreshToken) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("authkit")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(ACCESS_TOKEN_TTL_SECONDS))
                .subject(user.getId().toString())
                .id(refreshToken.jti()) // DT 3.2.3: bind access token to refresh session JTI
                .claim("tenantId", user.getTenantId().toString())
                .claim("tenant_id", user.getTenantId().toString())
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        LoginResponse responseDto = new LoginResponse(accessToken, ACCESS_TOKEN_TTL_SECONDS);
        return new LoginResult(responseDto, refreshToken.rawToken());
    }

    private boolean matchesWithCapacity(String rawPassword, String encodedPassword) {
        boolean acquired = argon2Semaphore.tryAcquire();
        if (!acquired) {
            throw new AuthenticationCapacityExceededException();
        }

        try {
            return passwordEncoder.matches(rawPassword, encodedPassword);
        } finally {
            argon2Semaphore.release();
        }
    }
}
