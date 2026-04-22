package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.Semaphore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.github.brenomega.authkit.domain.user.dto.LoginRequest;
import io.github.brenomega.authkit.domain.user.dto.LoginResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

import io.github.brenomega.authkit.infrastructure.aop.LogExecutionTime;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtEncoder jwtEncoder;
    private final TokenStorage tokenStorage;

    // Concurrency Limit (N = cores * 1.5) to brutally protect against Thread Exhaustion
    private final Semaphore argon2Semaphore;
    
    // DT 3.2.23 Progressive Lockout state
    private final Cache<String, Integer> failedAttemptsCache;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtEncoder jwtEncoder, TokenStorage tokenStorage) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtEncoder = jwtEncoder;
        this.tokenStorage = tokenStorage;
        
        int permits = (int) (Runtime.getRuntime().availableProcessors() * 1.5);
        this.argon2Semaphore = new Semaphore(Math.max(2, permits)); 
        this.failedAttemptsCache = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(Duration.ofMinutes(15))
                .build();
    }

    /**
     * Reusable container holding both public and restricted tokens post login.
     */
    public record LoginResult(LoginResponse response, String refreshToken) {}

    /**
     * Executes the secure identity negotiation lifecycle (RF 2.1.2).
     */
    @LogExecutionTime
    public LoginResult login(LoginRequest request) {
        String email = request.email();
        Integer attempts = failedAttemptsCache.getIfPresent(email);
        
        // DT 3.2.15 & DT 3.2.23: Stealth Lockout returning fake Success properties hiding Enumeration limits
        if (attempts != null && attempts >= 5) {
            log.warn("Stealth lockout active for email. Returning fake 200 OK token.");
            return new LoginResult(new LoginResponse("stealth-locked", 0), "stealth-locked");
        }

        // Enforce generic 401 to prevent enumeration
        User user = userRepository.findByEmail(email)
                .orElseThrow(InvalidCredentialsException::new);
                
        boolean passwordMatches = false;
        try {
            // Apply Semaphore logic dropping processing unconditionally when congested (DT 3.2.15)
            if (!argon2Semaphore.tryAcquire()) {
                // If system is overwhelmed, fail early explicitly via Stealth response emulation logic (HTTP 200/401 generically)
                throw new InvalidCredentialsException();
            }
            passwordMatches = passwordEncoder.matches(request.password(), user.getPassword());
        } finally {
            argon2Semaphore.release();
        }

        if (!passwordMatches) {
            failedAttemptsCache.put(email, attempts == null ? 1 : attempts + 1);
            throw new InvalidCredentialsException();
        }
        
        // Clear limits on legit sign in
        failedAttemptsCache.invalidate(email);

        // Generate Access Token (JWT)
        Instant now = Instant.now();
        long expiresInSeconds = 900; // 15 mins (Best practice TTL)

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("authkit")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiresInSeconds))
                .subject(user.getId())
                .claim("tenantId", user.getTenantId()) // Bind multitenant boundary explicitly
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        // Generate high-entropy secure Random UUID strictly for the Refresh Token
        String rawRefreshToken = UUID.randomUUID().toString();
        
        // TTL 7 days explicitly delegated to SPI
        tokenStorage.storeRefreshToken(user.getId(), rawRefreshToken, 7);

        LoginResponse responseDto = new LoginResponse(accessToken, expiresInSeconds);
        return new LoginResult(responseDto, rawRefreshToken);
    }
}
