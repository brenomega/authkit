package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import io.github.brenomega.authkit.domain.mfa.util.MfaChallengeCodec;
import io.github.brenomega.authkit.domain.user.dto.LoginRequest;
import io.github.brenomega.authkit.domain.user.dto.MfaLoginVerificationRequest;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.exception.EmailNotConfirmedException;
import io.github.brenomega.authkit.exception.InvalidCredentialsException;
import io.github.brenomega.authkit.exception.InvalidMfaCodeException;
import io.github.brenomega.authkit.exception.InvalidRefreshTokenException;
import io.github.brenomega.authkit.repository.UserRepository;
import io.github.brenomega.authkit.service.spi.TokenStorage;
import io.github.brenomega.authkit.infrastructure.audit.SecurityEventService;
import io.github.brenomega.authkit.infrastructure.security.AccountLockoutService;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

/**
 * Unit tests for AuthService (DT 3.4.5).
 * Validates the secure identity negotiation lifecycle (RF 2.1.2)
 * and progressive lockout via AccountLockoutService (DT 3.2.23).
 */
class AuthServiceTest {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private JwtEncoder jwtEncoder;
    private TokenStorage tokenStorage;
    private AccountLockoutService lockoutService;
    private AuthProperties authProperties;
    private SecurityEventService securityEventService;
    private MfaService mfaService;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        jwtEncoder = mock(JwtEncoder.class);
        tokenStorage = mock(TokenStorage.class);
        // Use a real AccountLockoutService with a mock Redis template.
        // Redis client is empty, causing fail-open to Caffeine — suitable for unit tests.
        lockoutService = new AccountLockoutService(Optional.empty());
        authProperties = new AuthProperties();
        securityEventService = mock(SecurityEventService.class);
        mfaService = mock(MfaService.class);
        when(mfaService.isMfaEnabled(any(User.class))).thenReturn(false);
        authService = new AuthService(userRepository, passwordEncoder, jwtEncoder, tokenStorage, lockoutService, authProperties, new Argon2ConcurrencyLimiter(), securityEventService, mfaService);
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
        when(user.getId()).thenReturn(java.util.UUID.fromString("00000000-0000-0000-0000-000000000000"));
        when(user.getEmail()).thenReturn(email);
        when(user.getPassword()).thenReturn("hashed-pass");
        when(user.getTenantId()).thenReturn(java.util.UUID.fromString("00000000-0000-0000-0000-000000000001"));
        when(user.isEmailConfirmed()).thenReturn(true);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(pass, user.getPassword())).thenReturn(true);
        
        Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("mock-access-token");
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        AuthService.LoginResult result = authService.login(new LoginRequest(email, pass));

        assertNotNull(result);
        assertEquals("mock-access-token", result.response().accessToken());
        assertEquals(900L, result.response().expiresIn());
        assertNotNull(result.refreshToken());
        verify(tokenStorage).storeRefreshToken(any(), any(), any(), eq(7L));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Login: Uses externalized issuer and token lifetime settings")
    void login_UsesExternalizedAuthSettings() {
        authProperties.getJwt().setIssuer("https://issuer.example.test");
        authProperties.getToken().setAccessTokenTtlSeconds(1200);
        authProperties.getToken().setRefreshTokenTtlDays(14);

        String email = "settings@example.com";
        String pass = "Pass123!";

        User user = mock(User.class);
        when(user.getId()).thenReturn(java.util.UUID.fromString("00000000-0000-0000-0000-000000000000"));
        when(user.getEmail()).thenReturn(email);
        when(user.getPassword()).thenReturn("hashed-pass");
        when(user.getTenantId()).thenReturn(java.util.UUID.fromString("00000000-0000-0000-0000-000000000001"));
        when(user.isEmailConfirmed()).thenReturn(true);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(pass, user.getPassword())).thenReturn(true);

        Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("configured-access-token");
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        AuthService.LoginResult result = authService.login(new LoginRequest(email, pass));

        assertEquals(1200L, result.response().expiresIn());
        verify(tokenStorage).storeRefreshToken(anyString(), anyString(), anyString(), eq(14L));

        ArgumentCaptor<JwtEncoderParameters> parameters = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(jwtEncoder).encode(parameters.capture());
        assertEquals("https://issuer.example.test", parameters.getValue().getClaims().getClaims().get("iss").toString());
        assertEquals(java.util.List.of("authkit-api"), parameters.getValue().getClaims().getClaims().get("aud"));
        assertEquals(
                "00000000-0000-0000-0000-000000000001",
                parameters.getValue().getClaims().getClaims().get("tenant_id"));
        org.junit.jupiter.api.Assertions.assertFalse(parameters.getValue().getClaims().getClaims().containsKey("tenantId"));
    }

    @Test
    @DisplayName("Login: MFA-enabled users receive only a one-time MFA challenge")
    void login_MfaEnabled_IssuesChallengeWithoutSession() {
        String email = "mfa@example.com";
        String pass = "Pass123!";
        String userId = "00000000-0000-0000-0000-000000000010";

        User user = mock(User.class);
        when(user.getId()).thenReturn(java.util.UUID.fromString(userId));
        when(user.getEmail()).thenReturn(email);
        when(user.getPassword()).thenReturn("hashed-pass");
        when(user.isEmailConfirmed()).thenReturn(true);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(pass, user.getPassword())).thenReturn(true);
        when(mfaService.isMfaEnabled(user)).thenReturn(true);

        AuthService.LoginResult result = authService.login(new LoginRequest(email, pass));

        assertTrue(result.response().mfaRequired());
        assertNotNull(result.response().mfaToken());
        assertNull(result.response().accessToken());
        assertNull(result.refreshToken());
        verify(tokenStorage).storeMfaChallenge(eq(userId), anyString(), eq(result.response().mfaToken()), eq(5L));
        verify(tokenStorage, never()).storeRefreshToken(anyString(), anyString(), anyString(), org.mockito.ArgumentMatchers.anyLong());
        verify(jwtEncoder, never()).encode(any(JwtEncoderParameters.class));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("MFA login: Valid challenge and code issue token pair with MFA claims")
    void verifyMfaLogin_Success_IssuesSession() {
        String userId = "00000000-0000-0000-0000-000000000011";
        String tenantId = "00000000-0000-0000-0000-000000000012";
        var challenge = MfaChallengeCodec.issue(userId);

        User user = mock(User.class);
        when(user.getId()).thenReturn(java.util.UUID.fromString(userId));
        when(user.getEmail()).thenReturn("mfa-login@example.com");
        when(user.getTenantId()).thenReturn(java.util.UUID.fromString(tenantId));
        when(user.isEmailConfirmed()).thenReturn(true);

        when(userRepository.findById(java.util.UUID.fromString(userId))).thenReturn(Optional.of(user));
        when(tokenStorage.consumeMfaChallenge(userId, challenge.jti(), challenge.rawToken())).thenReturn(true);
        when(mfaService.verifyMfaCode(user, "123456", "login_mfa"))
                .thenReturn(MfaService.MfaVerificationResult.totp());

        Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("mfa-access-token");
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        AuthService.LoginResult result = authService.verifyMfaLogin(
                new MfaLoginVerificationRequest(challenge.rawToken(), "123456"));

        assertEquals("mfa-access-token", result.response().accessToken());
        assertNotNull(result.refreshToken());
        verify(tokenStorage).storeRefreshToken(eq(userId), anyString(), anyString(), eq(7L));

        ArgumentCaptor<JwtEncoderParameters> parameters = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(jwtEncoder).encode(parameters.capture());
        assertEquals(java.util.List.of("pwd", "otp"), parameters.getValue().getClaims().getClaims().get("amr"));
        assertEquals(Boolean.TRUE, parameters.getValue().getClaims().getClaims().get("mfa"));
    }

    @Test
    @DisplayName("MFA login: Expired or replayed challenge is rejected before token issuance")
    void verifyMfaLogin_InvalidChallenge_ThrowsException() {
        String userId = "00000000-0000-0000-0000-000000000013";
        var challenge = MfaChallengeCodec.issue(userId);

        User user = mock(User.class);
        when(userRepository.findById(java.util.UUID.fromString(userId))).thenReturn(Optional.of(user));
        when(tokenStorage.consumeMfaChallenge(userId, challenge.jti(), challenge.rawToken())).thenReturn(false);

        assertThrows(InvalidMfaCodeException.class, () ->
                authService.verifyMfaLogin(new MfaLoginVerificationRequest(challenge.rawToken(), "123456")));

        verify(mfaService, never()).verifyMfaCode(any(), anyString(), anyString());
        verify(tokenStorage, never()).storeRefreshToken(anyString(), anyString(), anyString(), org.mockito.ArgumentMatchers.anyLong());
        verify(jwtEncoder, never()).encode(any(JwtEncoderParameters.class));
    }

    @Test
    @DisplayName("Login: Confirmed email is required before token issuance")
    void login_UnconfirmedEmail_ThrowsException() {
        String email = "unconfirmed@example.com";
        String pass = "Pass123!";

        User user = mock(User.class);
        when(user.getPassword()).thenReturn("hashed-pass");
        EmailNotConfirmedException ex = new EmailNotConfirmedException();
        org.mockito.Mockito.doThrow(ex).when(user).requireEmailConfirmed();
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(pass, user.getPassword())).thenReturn(true);

        assertThrows(EmailNotConfirmedException.class, () ->
                authService.login(new LoginRequest(email, pass)));
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
     * DT 3.2.23 — Progressive Lockout: Verifies generic rejection after 5 failed attempts.
     */
    @Test
    @DisplayName("Login: Generic rejection after lockout (DT 3.2.23)")
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

        // 6th attempt should remain indistinguishable from invalid credentials.
        assertThrows(InvalidCredentialsException.class, () ->
                authService.login(new LoginRequest(email, "any")));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Refresh: Valid refresh token rotates session and returns new access token")
    void refresh_Success_RotatesToken() {
        String userId = "00000000-0000-0000-0000-000000000000";
        String tenantId = "00000000-0000-0000-0000-000000000001";
        RefreshTokenCodec.IssuedRefreshToken currentToken =
                RefreshTokenCodec.issue(userId, "11111111-1111-1111-1111-111111111111");

        User user = mock(User.class);
        when(user.getId()).thenReturn(java.util.UUID.fromString(userId));
        when(user.getEmail()).thenReturn("refresh@example.com");
        when(user.getTenantId()).thenReturn(java.util.UUID.fromString(tenantId));
        when(user.isEmailConfirmed()).thenReturn(true);
        when(userRepository.findById(java.util.UUID.fromString(userId))).thenReturn(Optional.of(user));
        when(tokenStorage.rotateRefreshToken(
                eq(userId),
                eq(currentToken.jti()),
                eq(currentToken.rawToken()),
                anyString(),
                anyString(),
                eq(7L)
        )).thenReturn(true);

        Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("rotated-access-token");
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        AuthService.LoginResult result = authService.refresh(currentToken.rawToken());

        assertEquals("rotated-access-token", result.response().accessToken());
        assertNotNull(result.refreshToken());
        assertNotNull(RefreshTokenCodec.parse(result.refreshToken()).orElse(null));
    }

    @Test
    @DisplayName("Refresh: Malformed refresh token is rejected")
    void refresh_MalformedToken_ThrowsException() {
        assertThrows(InvalidRefreshTokenException.class, () -> authService.refresh("not-a-valid-token"));
    }

    @Test
    @DisplayName("Logout: Valid refresh token revokes the referenced session")
    void logout_RevokesSession() {
        String userId = "00000000-0000-0000-0000-000000000000";
        String jti = "11111111-1111-1111-1111-111111111111";
        RefreshTokenCodec.IssuedRefreshToken token = RefreshTokenCodec.issue(userId, jti);
        when(tokenStorage.validateToken(userId, jti, token.rawToken())).thenReturn(true);

        authService.logout(token.rawToken());

        verify(tokenStorage).revokeSession(userId, jti);
    }

    @Test
    @DisplayName("Logout: Missing or malformed refresh token is idempotent")
    void logout_MalformedToken_Noops() {
        authService.logout("malformed");

        verify(tokenStorage, never()).revokeSession(anyString(), anyString());
    }

    @Test
    @DisplayName("Logout all: MFA step-up is enforced when configured for the account")
    void logoutAll_RequiresMfaWhenEnabled() {
        String userId = "00000000-0000-0000-0000-000000000014";
        User user = mock(User.class);
        when(userRepository.findById(java.util.UUID.fromString(userId))).thenReturn(Optional.of(user));

        authService.logoutAll(userId, "123456");

        verify(mfaService).requireMfaIfEnabled(user, "123456", "logout_all");
        verify(tokenStorage).revokeAllSessions(userId);
    }
}
