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
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

import io.github.brenomega.authkit.infrastructure.aop.LogExecutionTime;
import io.github.brenomega.authkit.infrastructure.cache.AccountLockoutService;

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
     * and all subsequent login attempts return a stealth 200 OK response (DT 3.2.15)
     * to prevent enumeration.</p>
     *
     * @param request the login credentials
     * @return a {@link LoginResult} containing the access and refresh tokens
     */
    @LogExecutionTime
    public LoginResult login(LoginRequest request) {
        String email = request.email();
        
        // DT 3.2.15 & DT 3.2.23: Stealth Lockout returning fake Success properties hiding Enumeration limits
        if (lockoutService.isLocked(email)) {
            log.warn("Stealth lockout active for email. Returning fake 200 OK token.");
            return new LoginResult(new LoginResponse("stealth-locked", 0), "stealth-locked");
        }

        // Enforce generic 401 to prevent enumeration
        User user = userRepository.findByEmail(email)
                .orElseThrow(InvalidCredentialsException::new);
                
        boolean passwordMatches;
        try {
            // Apply Semaphore logic dropping processing unconditionally when congested (DT 3.2.26)
            if (!argon2Semaphore.tryAcquire()) {
                // If system is overwhelmed, fail early explicitly via Stealth response emulation logic
                throw new InvalidCredentialsException();
            }
            passwordMatches = passwordEncoder.matches(request.password(), user.getPassword());
        } finally {
            argon2Semaphore.release();
        }

        if (!passwordMatches) {
            lockoutService.recordFailedAttempt(email);
            throw new InvalidCredentialsException();
        }
        
        // Clear limits on legit sign in
        lockoutService.clearLockout(email);

        // Generate high-entropy secure Random UUID strictly for the Refresh Token
        String jti = UUID.randomUUID().toString();
        String rawRefreshToken = UUID.randomUUID().toString();
        
        // Generate Access Token (JWT)
        Instant now = Instant.now();
        long expiresInSeconds = 900; // 15 mins (Best practice TTL)

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("authkit")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiresInSeconds))
                .subject(user.getId().toString())
                .id(jti) // DT 3.2.3: jti claim for session identification
                .claim("tenantId", user.getTenantId().toString()) // Bind multitenant boundary explicitly
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        
        // TTL 7 days explicitly delegated to SPI
        tokenStorage.storeRefreshToken(user.getId().toString(), jti, rawRefreshToken, 7);

        LoginResponse responseDto = new LoginResponse(accessToken, expiresInSeconds);
        return new LoginResult(responseDto, rawRefreshToken);
    }
}
