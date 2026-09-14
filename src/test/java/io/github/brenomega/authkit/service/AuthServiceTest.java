package io.github.brenomega.authkit.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import io.github.brenomega.authkit.domain.mfa.dto.MfaLoginVerificationRequest;
import io.github.brenomega.authkit.domain.mfa.util.MfaChallengeCodec;
import io.github.brenomega.authkit.domain.user.dto.LoginRequest;
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
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import io.github.brenomega.authkit.infrastructure.security.Argon2ConcurrencyLimiter;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.spi.SessionMetadata;

class AuthServiceTest {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private JwtEncoder jwtEncoder;
    private TokenStorage tokenStorage;
    private AccountLockoutService lockoutService;
    private AuthProperties authProperties;
    private SecurityEventService securityEventService;
    private MfaService mfaService;
    private AbuseThrottleService abuseThrottleService;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
        when(passwordEncoder.encode(anyString())).thenReturn("dummy-timing-hash");
        jwtEncoder = mock(JwtEncoder.class);
        tokenStorage = mock(TokenStorage.class);

        lockoutService = spy(new AccountLockoutService(Optional.empty()));
        authProperties = new AuthProperties();
        securityEventService = mock(SecurityEventService.class);
        mfaService = mock(MfaService.class);
        abuseThrottleService = mock(AbuseThrottleService.class);
        when(mfaService.isMfaEnabled(any(User.class))).thenReturn(false);
        SessionMetadataFactory sessionMetadataFactory = mock(SessionMetadataFactory.class);
        when(sessionMetadataFactory.create(anyString(), anyLong(), anyList(), anyLong())).thenAnswer(invocation -> {
            String jti = invocation.getArgument(0);
            Instant now = Instant.now();
            return new SessionMetadata(
                    UUID.randomUUID().toString(), jti, now, now, now.plusSeconds(604800),
                    invocation.getArgument(1), invocation.getArgument(2),
                    "JUnit", null, "127.0.0.***", "127.0.0.***");
        });
        authService = new AuthService(
            userRepository,
            passwordEncoder,
            jwtEncoder,
            tokenStorage,
            lockoutService,
            authProperties,
            new Argon2ConcurrencyLimiter(),
            securityEventService,
            mfaService,
            abuseThrottleService,
            sessionMetadataFactory);
    }

    @Test
    @DisplayName("Login: Successful authentication returns tokens")
    void login_Success() {
        String email = "test@example.com";
        String pass = "Pass123!";

        User user = mock(User.class);
        when(user.getId()).thenReturn(UUID.fromString("00000000-0000-0000-0000-000000000000"));
        when(user.getEmail()).thenReturn(email);
        when(user.getPassword()).thenReturn("hashed-pass");
        when(user.getTenantId()).thenReturn(UUID.fromString("00000000-0000-0000-0000-000000000001"));
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
        verify(tokenStorage).storeRefreshToken(any(), any(), any(), eq(7L), any());
        verify(lockoutService).clearLockout(email);
    }

    @Test
    @DisplayName("Login: dummy timing hash can never authenticate a passwordless social identity")
    void login_PasswordlessAccountRejectsEvenWhenInputMatchesDummyHash() {
        String email = "social-only@example.com";
        User user = mock(User.class);
        when(user.getEmail()).thenReturn(email);
        when(user.getPassword()).thenReturn(null);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("AuthKit dummy password for timing equalization", "dummy-timing-hash"))
                .thenReturn(true);

        assertThrows(InvalidCredentialsException.class, () -> authService.login(new LoginRequest(
                email, "AuthKit dummy password for timing equalization")));

        verify(jwtEncoder, never()).encode(any(JwtEncoderParameters.class));
        verify(tokenStorage, never()).storeRefreshToken(anyString(), anyString(), anyString(), anyLong(), any());
        verify(mfaService, never()).isMfaEnabled(user);
    }

    @Test
    @DisplayName("Login: Uses externalized issuer and token lifetime settings")
    void login_UsesExternalizedAuthSettings() {
        authProperties.getJwt().setIssuer("https://issuer.example.test");
        authProperties.getToken().setAccessTokenTtlSeconds(1200);
        authProperties.getToken().setRefreshTokenTtlDays(14);

        String email = "settings@example.com";
        String pass = "Pass123!";

        User user = mock(User.class);
        when(user.getId()).thenReturn(UUID.fromString("00000000-0000-0000-0000-000000000000"));
        when(user.getEmail()).thenReturn(email);
        when(user.getPassword()).thenReturn("hashed-pass");
        when(user.getTenantId()).thenReturn(UUID.fromString("00000000-0000-0000-0000-000000000001"));
        when(user.isEmailConfirmed()).thenReturn(true);

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(pass, user.getPassword())).thenReturn(true);

        Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("configured-access-token");
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        AuthService.LoginResult result = authService.login(new LoginRequest(email, pass));

        assertEquals(1200L, result.response().expiresIn());
        verify(tokenStorage).storeRefreshToken(anyString(), anyString(), anyString(), eq(14L), any());

        ArgumentCaptor<JwtEncoderParameters> parameters = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(jwtEncoder).encode(parameters.capture());
        assertEquals(
            "https://issuer.example.test",
            parameters.getValue().getClaims().getClaims().get("iss").toString());
        assertEquals(List.of("authkit-api"), parameters.getValue().getClaims().getClaims().get("aud"));
        assertEquals(
                "00000000-0000-0000-0000-000000000001",
                parameters.getValue().getClaims().getClaims().get("tenant_id"));
        org.junit.jupiter.api.Assertions.assertFalse(
                parameters.getValue().getClaims().getClaims().containsKey("tenantId"));
    }

    @Test
    @DisplayName("Login: MFA-enabled users receive only a one-time MFA challenge")
    void login_MfaEnabled_IssuesChallengeWithoutSession() {
        String email = "mfa@example.com";
        String pass = "Pass123!";
        String userId = "00000000-0000-0000-0000-000000000010";

        User user = mock(User.class);
        when(user.getId()).thenReturn(UUID.fromString(userId));
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
        verify(
            tokenStorage,
            never()).storeRefreshToken(anyString(), anyString(), anyString(), org.mockito.ArgumentMatchers.anyLong());
        verify(jwtEncoder, never()).encode(any(JwtEncoderParameters.class));
        verify(lockoutService, never()).clearLockout(email);
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("MFA login: Valid challenge and code issue token pair with MFA claims")
    void verifyMfaLogin_Success_IssuesSession() {
        String userId = "00000000-0000-0000-0000-000000000011";
        String tenantId = "00000000-0000-0000-0000-000000000012";
        var challenge = MfaChallengeCodec.issue(userId);

        User user = mock(User.class);
        when(user.getId()).thenReturn(UUID.fromString(userId));
        when(user.getEmail()).thenReturn("mfa-login@example.com");
        when(user.getTenantId()).thenReturn(UUID.fromString(tenantId));
        when(user.isEmailConfirmed()).thenReturn(true);
        when(user.isActive()).thenReturn(true);
        when(user.hasCurrentConsent("terms-v1", "privacy-v1")).thenReturn(true);
        when(user.acceptsSession(anyString(), anyLong())).thenReturn(true);

        when(userRepository.findById(UUID.fromString(userId))).thenReturn(Optional.of(user));
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
        verify(tokenStorage).storeRefreshToken(eq(userId), anyString(), anyString(), eq(7L), any());

        ArgumentCaptor<JwtEncoderParameters> parameters = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(jwtEncoder).encode(parameters.capture());
        assertEquals(List.of("pwd", "otp"), parameters.getValue().getClaims().getClaims().get("amr"));
        assertEquals(Boolean.TRUE, parameters.getValue().getClaims().getClaims().get("mfa"));
        verify(lockoutService).clearLockout("mfa-login@example.com");
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("MFA login: Invalid code records account lockout pressure and does not issue tokens")
    void verifyMfaLogin_InvalidCode_RecordsFailedAttemptAndDoesNotIssueSession() {
        String userId = "00000000-0000-0000-0000-000000000015";
        var challenge = MfaChallengeCodec.issue(userId);

        User user = mock(User.class);
        when(user.getId()).thenReturn(UUID.fromString(userId));
        when(user.getEmail()).thenReturn("mfa-fail@example.com");
        when(user.isEmailConfirmed()).thenReturn(true);
        when(user.isActive()).thenReturn(true);
        when(user.hasCurrentConsent("terms-v1", "privacy-v1")).thenReturn(true);

        when(userRepository.findById(UUID.fromString(userId))).thenReturn(Optional.of(user));
        when(tokenStorage.consumeMfaChallenge(userId, challenge.jti(), challenge.rawToken())).thenReturn(true);
        when(mfaService.verifyMfaCode(user, "000000", "login_mfa"))
                .thenReturn(MfaService.MfaVerificationResult.invalid());

        assertThrows(InvalidMfaCodeException.class, () ->
                authService.verifyMfaLogin(new MfaLoginVerificationRequest(challenge.rawToken(), "000000")));

        verify(lockoutService).recordFailedAttempt("mfa-fail@example.com");
        verify(
            tokenStorage,
            never()).storeRefreshToken(anyString(), anyString(), anyString(), org.mockito.ArgumentMatchers.anyLong());
        verify(jwtEncoder, never()).encode(any(JwtEncoderParameters.class));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("MFA login: Expired or replayed challenge is rejected before token issuance")
    void verifyMfaLogin_InvalidChallenge_ThrowsException() {
        String userId = "00000000-0000-0000-0000-000000000013";
        var challenge = MfaChallengeCodec.issue(userId);

        User user = mock(User.class);
        when(user.getEmail()).thenReturn("mfa-expired@example.com");
        when(userRepository.findById(UUID.fromString(userId))).thenReturn(Optional.of(user));
        when(tokenStorage.consumeMfaChallenge(userId, challenge.jti(), challenge.rawToken())).thenReturn(false);

        assertThrows(InvalidMfaCodeException.class, () ->
                authService.verifyMfaLogin(new MfaLoginVerificationRequest(challenge.rawToken(), "123456")));

        verify(mfaService, never()).verifyMfaCode(any(), anyString(), anyString());
        verify(
            tokenStorage,
            never()).storeRefreshToken(anyString(), anyString(), anyString(), org.mockito.ArgumentMatchers.anyLong());
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

    @Test
    @DisplayName("Login: Invalid credentials throw generic exception (DT 3.2.15)")
    void login_InvalidCredentials_ThrowsException() {
        String email = "test@example.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        assertThrows(InvalidCredentialsException.class, () ->
            authService.login(new LoginRequest(email, "any-pass")));
    }

    @Test
    @DisplayName("Login: Generic rejection after lockout (DT 3.2.23)")
    void login_StealthLockout() {
        String email = "locked@example.com";
        User user = mock(User.class);
        when(user.getPassword()).thenReturn("hashed");

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(any(), any())).thenReturn(false);

        for (int i = 0; i < 5; i++) {
            assertThrows(InvalidCredentialsException.class, () ->
                authService.login(new LoginRequest(email, "wrong")));
        }

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
        when(user.getId()).thenReturn(UUID.fromString(userId));
        when(user.getEmail()).thenReturn("refresh@example.com");
        when(user.getTenantId()).thenReturn(UUID.fromString(tenantId));
        when(user.isEmailConfirmed()).thenReturn(true);
        when(user.isActive()).thenReturn(true);
        when(user.hasCurrentConsent("terms-v1", "privacy-v1")).thenReturn(true);
        when(user.acceptsSession(anyString(), anyLong())).thenReturn(true);
        when(userRepository.findById(UUID.fromString(userId))).thenReturn(Optional.of(user));
        when(tokenStorage.rotateRefreshToken(
                eq(userId),
                eq(currentToken.jti()),
                eq(currentToken.rawToken()),
                anyString(),
                anyString(),
                eq(7L),
                eq(0L)
        )).thenReturn(true);
        when(tokenStorage.findSessionMetadata(eq(userId), anyString()))
                .thenReturn(Optional.of(new SessionMetadata(
                        "session", "next-jti", java.time.Instant.now(), java.time.Instant.now(),
                        java.time.Instant.now().plusSeconds(3600), 0, List.of("pwd"),
                        "JUnit", null, "127.0.0.***", "127.0.0.***")));

        Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("rotated-access-token");
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        AuthService.LoginResult result = authService.refresh(currentToken.rawToken());

        assertEquals("rotated-access-token", result.response().accessToken());
        assertNotNull(result.refreshToken());
        assertNotNull(RefreshTokenCodec.parse(result.refreshToken()).orElse(null));
    }

    @SuppressWarnings("null")
    @ParameterizedTest(name = "AMR {0} survives refresh with mfa={1}")
    @MethodSource("authenticationProvenance")
    void authenticationProvenanceIsExactBeforeAndAfterRefresh(List<String> amr, boolean expectedMfa) {
        String userId = UUID.randomUUID().toString();
        User user = mock(User.class);
        when(user.getId()).thenReturn(UUID.fromString(userId));
        when(user.getEmail()).thenReturn("amr-" + UUID.randomUUID() + "@example.test");
        when(user.getTenantId()).thenReturn(UUID.randomUUID());
        when(user.isActive()).thenReturn(true);
        when(user.isEmailConfirmed()).thenReturn(true);
        when(user.hasCurrentConsent("terms-v1", "privacy-v1")).thenReturn(true);
        when(user.acceptsSession(anyString(), anyLong())).thenReturn(true);
        when(userRepository.findById(UUID.fromString(userId))).thenReturn(Optional.of(user));
        when(mfaService.isMfaEnabled(user)).thenReturn(true); // Enrollment alone must not alter the supplied AMR.

        Jwt jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("amr-access-token");
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        AuthService.LoginResult initial = authService.issueLoginForVerifiedUser(user, amr, "amr_matrix");
        RefreshTokenCodec.IssuedRefreshToken current = RefreshTokenCodec.parse(initial.refreshToken()).orElseThrow();
        when(tokenStorage.rotateRefreshToken(eq(userId), eq(current.jti()), eq(current.rawToken()),
                anyString(), anyString(), eq(7L), eq(0L))).thenReturn(true);
        when(tokenStorage.findSessionMetadata(eq(userId), anyString())).thenReturn(Optional.of(new SessionMetadata(
                "session", "rotated", Instant.now(), Instant.now(), Instant.now().plusSeconds(3600), 0,
                amr, "JUnit", null, "127.0.0.***", "127.0.0.***")));

        authService.refresh(initial.refreshToken());

        ArgumentCaptor<JwtEncoderParameters> claims = ArgumentCaptor.forClass(JwtEncoderParameters.class);
        verify(jwtEncoder, org.mockito.Mockito.times(2)).encode(claims.capture());
        for (JwtEncoderParameters parameters : claims.getAllValues()) {
            assertEquals(amr, parameters.getClaims().getClaims().get("amr"));
            assertEquals(expectedMfa, parameters.getClaims().getClaims().get("mfa"));
        }
    }

    private static Stream<Arguments> authenticationProvenance() {
        return Stream.of(
                Arguments.of(List.of("pwd"), false),
                Arguments.of(List.of("pwd", "otp"), true),
                Arguments.of(List.of("pwd", "backup_code"), true),
                Arguments.of(List.of("webauthn"), false),
                Arguments.of(List.of("federated", "oidc:google"), false));
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Refresh: Deleted accounts are rejected before token rotation")
    void refresh_DeletedUser_ThrowsAndDoesNotRotate() {
        String userId = "00000000-0000-0000-0000-000000000016";
        RefreshTokenCodec.IssuedRefreshToken currentToken =
                RefreshTokenCodec.issue(userId, "11111111-1111-1111-1111-111111111116");

        User user = mock(User.class);
        when(user.getId()).thenReturn(UUID.fromString(userId));
        when(user.getEmail()).thenReturn("deleted-refresh@example.com");
        when(user.isEmailConfirmed()).thenReturn(true);
        when(user.isDeleted()).thenReturn(true);
        when(userRepository.findById(UUID.fromString(userId))).thenReturn(Optional.of(user));

        assertThrows(InvalidRefreshTokenException.class, () -> authService.refresh(currentToken.rawToken()));

        verify(tokenStorage, never()).rotateRefreshToken(
                anyString(),
                anyString(),
                anyString(),
                anyString(),
                anyString(),
                org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.anyLong());
        verify(jwtEncoder, never()).encode(any(JwtEncoderParameters.class));
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

        verify(tokenStorage).revokeSessionByJti(userId, jti);
    }

    @Test
    @DisplayName("Logout: Missing or malformed refresh token is idempotent")
    void logout_MalformedToken_Noops() {
        authService.logout("malformed");

        verify(tokenStorage, never()).revokeSession(anyString(), anyString());
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Logout all: MFA step-up is enforced when configured for the account")
    void logoutAll_RequiresMfaWhenEnabled() {
        String userId = "00000000-0000-0000-0000-000000000014";
        User user = mock(User.class);
        when(user.isActive()).thenReturn(true);
        when(userRepository.findById(UUID.fromString(userId))).thenReturn(Optional.of(user));

        authService.logoutAll(userId, "123456");

        verify(mfaService).requireMfaIfEnabled(user, "123456", "logout_all");
        verify(tokenStorage).revokeAllSessions(userId);
    }
}
