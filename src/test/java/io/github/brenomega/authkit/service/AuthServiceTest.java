package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import io.github.brenomega.authkit.domain.user.dto.LoginRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;

/**
 * Unit tests for AuthService (DT 3.4.5).
 * Validates the secure identity negotiation lifecycle (RF 2.1.2).
 */
class AuthServiceTest {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private JwtEncoder jwtEncoder;
    private TokenStorage tokenStorage;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        jwtEncoder = mock(JwtEncoder.class);
        tokenStorage = mock(TokenStorage.class);
        authService = new AuthService(userRepository, passwordEncoder, jwtEncoder, tokenStorage);
    }

    /**
     * DT 3.2.1 — Argon2id Matching: Confirms successful login when credentials match.
     */
    @Test
    @DisplayName("Login: Successful authentication returns tokens")
    void login_Success() {
        String email = "test@example.com";
        String pass = "Pass123!";
        
        User user = mock(User.class);
        when(user.getId()).thenReturn("user-id");
        when(user.getEmail()).thenReturn(email);
        when(user.getPassword()).thenReturn("hashed-pass");
        when(user.getTenantId()).thenReturn("tenant-id");

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(pass, user.getPassword())).thenReturn(true);
        
        Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("mock-access-token");
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        AuthService.LoginResult result = authService.login(new LoginRequest(email, pass));

        assertNotNull(result);
        assertEquals("mock-access-token", result.response().accessToken());
        verify(tokenStorage).storeRefreshToken(any(), any(), any(Long.class));
    }

    /**
     * DT 3.2.15 — Stealth Response: Ensures generic exception on invalid credentials to prevent enumeration.
     */
    @Test
    @DisplayName("Login: Invalid credentials throw generic exception (DT 3.2.15)")
    void login_InvalidCredentials_ThrowsException() {
        String email = "test@example.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        assertThrows(InvalidCredentialsException.class, () -> 
            authService.login(new LoginRequest(email, "any-pass")));
    }

    /**
     * DT 3.2.23 — Progressive Lockout: Verifies stealth response after 5 failed attempts.
     */
    @Test
    @DisplayName("Login: Stealth lockout after 5 failures (DT 3.2.23)")
    void login_StealthLockout() {
        String email = "locked@example.com";
        User user = mock(User.class);
        when(user.getPassword()).thenReturn("hashed");
        
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(any(), any())).thenReturn(false);

        // Fail 5 times
        for (int i = 0; i < 5; i++) {
            assertThrows(InvalidCredentialsException.class, () -> 
                authService.login(new LoginRequest(email, "wrong")));
        }

        // 6th attempt should be stealth-locked
        AuthService.LoginResult result = authService.login(new LoginRequest(email, "any"));
        assertEquals("stealth-locked", result.refreshToken());
        assertEquals("stealth-locked", result.response().accessToken());
    }
}
