package io.github.brenomega.authkit.service;

import java.time.Instant;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import io.github.brenomega.authkit.domain.user.dto.LoginRequest;
import io.github.brenomega.authkit.domain.user.dto.LoginResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtEncoder jwtEncoder;
    private final TokenStorage tokenStorage;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtEncoder jwtEncoder, TokenStorage tokenStorage) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtEncoder = jwtEncoder;
        this.tokenStorage = tokenStorage;
    }

    /**
     * Reusable container holding both public and restricted tokens post login.
     */
    public record LoginResult(LoginResponse response, String refreshToken) {}

    /**
     * Executes the secure identity negotiation lifecycle (RF 2.1.2).
     */
    public LoginResult login(LoginRequest request) {
        // Enforce generic 401 to prevent enumeration
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(InvalidCredentialsException::new);
                
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new InvalidCredentialsException();
        }

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
