package io.github.brenomega.authkit.controller;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.github.brenomega.authkit.domain.user.dto.LoginRequest;
import io.github.brenomega.authkit.domain.user.dto.LoginResponse;
import io.github.brenomega.authkit.domain.user.dto.EmailConfirmationResendRequest;
import io.github.brenomega.authkit.domain.user.dto.MfaLoginVerificationRequest;
import io.github.brenomega.authkit.domain.user.dto.MfaOptionalVerificationRequest;
import io.github.brenomega.authkit.domain.user.dto.PasskeyAssertionFinishRequest;
import io.github.brenomega.authkit.domain.user.dto.PasskeyAssertionOptionsRequest;
import io.github.brenomega.authkit.domain.user.dto.PasskeyAssertionOptionsResponse;
import io.github.brenomega.authkit.domain.user.dto.PasswordRecoveryRequest;
import io.github.brenomega.authkit.domain.user.dto.PasswordResetRequest;
import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.domain.user.dto.RegisterResponse;
import io.github.brenomega.authkit.domain.user.dto.RegistrationAcceptedResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.exception.InvalidCsrfTokenException;
import io.github.brenomega.authkit.exception.UserAlreadyExistsException;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.AuthService;
import io.github.brenomega.authkit.service.PasskeyService;
import io.github.brenomega.authkit.service.PasswordRecoveryService;
import io.github.brenomega.authkit.service.RegistrationService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

/**
 * Unified entry point for Identity and Access Management (IAM) (DT 3.1.1).
 *
 * <p>Handles Registration (RF 2.1.1), Login (RF 2.1.2), and Password
 * Recovery (RF 2.1.3, RF 2.1.4) to centralize security filter application
 * and documentation boundaries.</p>
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final RegistrationService registrationService;
    private final AuthService authService;
    private final PasswordRecoveryService recoveryService;
    private final PasskeyService passkeyService;
    private final AuthProperties authProperties;

    public AuthController(
            RegistrationService registrationService,
            AuthService authService,
            PasswordRecoveryService recoveryService,
            PasskeyService passkeyService,
            AuthProperties authProperties) {
        this.registrationService = registrationService;
        this.authService = authService;
        this.recoveryService = recoveryService;
        this.passkeyService = passkeyService;
        this.authProperties = authProperties;
    }

    /**
     * Executes the secure identity negotiation lifecycle (RF 2.1.2).
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest request) {
        AuthService.LoginResult result = authService.login(request);
        HttpHeaders headers = new HttpHeaders();
        if (StringUtils.hasText(result.refreshToken())) {
            addSessionCookies(headers, result.refreshToken());
        }

        return ResponseEntity.ok()
                .headers(headers)
                .body(ApiResponse.success(result.response()));
    }

    /**
     * Completes login for accounts protected by MFA.
     */
    @PostMapping("/mfa/verify-login")
    public ResponseEntity<ApiResponse<LoginResponse>> verifyMfaLogin(
            @Valid @RequestBody MfaLoginVerificationRequest request) {
        AuthService.LoginResult result = authService.verifyMfaLogin(request);
        HttpHeaders headers = new HttpHeaders();
        addSessionCookies(headers, result.refreshToken());

        return ResponseEntity.ok()
                .headers(headers)
                .body(ApiResponse.success(result.response()));
    }

    @PostMapping("/passkeys/options")
    public ResponseEntity<ApiResponse<PasskeyAssertionOptionsResponse>> passkeyOptions(
            @Valid @RequestBody(required = false) PasskeyAssertionOptionsRequest request) {
        return ResponseEntity.ok(ApiResponse.success(passkeyService.startAssertion(request)));
    }

    @PostMapping("/passkeys/verify")
    public ResponseEntity<ApiResponse<LoginResponse>> verifyPasskey(
            @Valid @RequestBody PasskeyAssertionFinishRequest request) {
        AuthService.LoginResult result = passkeyService.finishAssertion(request);
        HttpHeaders headers = new HttpHeaders();
        addSessionCookies(headers, result.refreshToken());

        return ResponseEntity.ok()
                .headers(headers)
                .body(ApiResponse.success(result.response()));
    }

    /**
     * Rotates the refresh token and issues a fresh access token (RF 2.1.5, DT 3.2.4).
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<LoginResponse>> refresh(HttpServletRequest request) {
        validateCsrfToken(request);

        AuthService.LoginResult result = authService.refresh(readRefreshToken(request));
        HttpHeaders headers = new HttpHeaders();
        addSessionCookies(headers, result.refreshToken());

        return ResponseEntity.ok()
                .headers(headers)
                .body(ApiResponse.success(result.response()));
    }

    /**
     * Revokes the current refresh-token-backed session and clears the cookie (RF 2.1.5).
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(HttpServletRequest request) {
        validateCsrfToken(request);

        authService.logout(readRefreshToken(request));
        HttpHeaders headers = new HttpHeaders();
        addClearedSessionCookies(headers);

        return ResponseEntity.ok()
                .headers(headers)
                .body(ApiResponse.success("Logged out successfully."));
    }

    /**
     * Revokes all active refresh-token-backed sessions for the authenticated user (RF 2.1.10).
     */
    @PostMapping("/logout-all")
    public ResponseEntity<ApiResponse<String>> logoutAll(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody(required = false) MfaOptionalVerificationRequest request) {
        authService.logoutAll(jwt.getSubject(), request == null ? null : request.code());
        HttpHeaders headers = new HttpHeaders();
        addClearedSessionCookies(headers);
        return ResponseEntity.ok()
                .headers(headers)
                .body(ApiResponse.success("All sessions successfully revoked."));
    }

    /**
     * Registers a new user account (RF 2.1.1).
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<?>> register(
            @Valid @RequestBody RegisterRequest request) {

        try {
            User user = registrationService.registerUser(request);
            if (authProperties.getRegistration().isStealthConflicts()) {
                return acceptedRegistrationResponse();
            }

            return createdRegistrationResponse(user);
        } catch (UserAlreadyExistsException ex) {
            if (authProperties.getRegistration().isStealthConflicts()) {
                return acceptedRegistrationResponse();
            }
            throw ex;
        }
    }

    private ResponseEntity<ApiResponse<?>> createdRegistrationResponse(User user) {
        RegisterResponse responseDto = new RegisterResponse(
                user.getId().toString(),
                user.getEmail(),
                user.getTenantId().toString()
        );

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(responseDto));
    }

    private ResponseEntity<ApiResponse<?>> acceptedRegistrationResponse() {
        return ResponseEntity.accepted()
                .body(ApiResponse.success(new RegistrationAcceptedResponse(
                        "If this registration can be processed, an activation email will be sent.")));
    }

    /**
     * Confirms a registered user's email address (RF 2.1.7).
     */
    @PostMapping("/email-confirmation/confirm")
    public ResponseEntity<ApiResponse<String>> confirmEmail(@RequestParam String token) {
        registrationService.confirmEmail(token);
        return ResponseEntity.ok(ApiResponse.success("Email confirmed successfully."));
    }

    @PostMapping("/email-confirmation/resend")
    public ResponseEntity<ApiResponse<String>> resendEmailConfirmation(
            @Valid @RequestBody EmailConfirmationResendRequest request) {
        registrationService.resendEmailConfirmation(request.email());
        return ResponseEntity.accepted().body(ApiResponse.success(
                "If this account is awaiting confirmation, a new activation email will be sent."));
    }

    /**
     * Initiates the password recovery flow (RF 2.1.3).
     *
     * <p><strong>Stealth Strategy (DT 3.2.15):</strong> Always returns a successful 
     * message regardless of email existence to prevent user enumeration.</p>
     */
    @PostMapping("/password-recovery/request")
    public ResponseEntity<ApiResponse<String>> requestRecovery(
            @Valid @RequestBody PasswordRecoveryRequest request) {
        
        recoveryService.requestRecovery(request.email());
        
        return ResponseEntity.ok(ApiResponse.success(
                "If an account exists with this email, a recovery link has been sent."));
    }

    /**
     * Executes the password reset using a secure token (RF 2.1.4).
     *
     * <p>Consumes the recovery token and updates the user credential using 
     * Argon2id (DT 3.2.1).</p>
     */
    @PostMapping("/password-recovery/reset")
    public ResponseEntity<ApiResponse<String>> resetPassword(
            @RequestParam String email,
            @Valid @RequestBody PasswordResetRequest request) {
        
        recoveryService.resetPassword(email, request.token(), request.newPassword());
        
        return ResponseEntity.ok(ApiResponse.success("Password successfully reset."));
    }

    @SuppressWarnings("null")
    private ResponseCookie refreshCookie(String refreshToken) {
        AuthProperties.Cookie cookie = authProperties.getCookie();

        // DT 3.2.22: HttpOnly cookie prevents client-side script access.
        return ResponseCookie.from(cookie.getRefreshName(), refreshToken)
                .httpOnly(cookie.isHttpOnly())
                .secure(cookie.isSecure())
                .sameSite(cookie.getSameSite())
                .path(cookie.getPath())
                .maxAge(Duration.ofDays(authProperties.getToken().getRefreshTokenTtlDays()))
                .build();
    }

    @SuppressWarnings("null")
    private ResponseCookie csrfCookie(String csrfToken) {
        AuthProperties.Cookie cookie = authProperties.getCookie();
        AuthProperties.Csrf csrf = authProperties.getCsrf();

        return ResponseCookie.from(csrf.getCookieName(), csrfToken)
                .httpOnly(false)
                .secure(cookie.isSecure())
                .sameSite(cookie.getSameSite())
                .path(csrf.getPath())
                .maxAge(Duration.ofDays(authProperties.getToken().getRefreshTokenTtlDays()))
                .build();
    }

    @SuppressWarnings("null")
    private ResponseCookie clearRefreshCookie() {
        AuthProperties.Cookie cookie = authProperties.getCookie();

        return ResponseCookie.from(cookie.getRefreshName(), "")
                .httpOnly(cookie.isHttpOnly())
                .secure(cookie.isSecure())
                .sameSite(cookie.getSameSite())
                .path(cookie.getPath())
                .maxAge(0)
                .build();
    }

    @SuppressWarnings("null")
    private ResponseCookie clearCsrfCookie() {
        AuthProperties.Cookie cookie = authProperties.getCookie();
        AuthProperties.Csrf csrf = authProperties.getCsrf();

        return ResponseCookie.from(csrf.getCookieName(), "")
                .httpOnly(false)
                .secure(cookie.isSecure())
                .sameSite(cookie.getSameSite())
                .path(csrf.getPath())
                .maxAge(0)
                .build();
    }

    private void addSessionCookies(HttpHeaders headers, String refreshToken) {
        headers.add(HttpHeaders.SET_COOKIE, refreshCookie(refreshToken).toString());
        if (authProperties.getCsrf().isEnabled()) {
            headers.add(HttpHeaders.SET_COOKIE, csrfCookie(newCsrfToken()).toString());
        }
    }

    private void addClearedSessionCookies(HttpHeaders headers) {
        headers.add(HttpHeaders.SET_COOKIE, clearRefreshCookie().toString());
        if (authProperties.getCsrf().isEnabled()) {
            headers.add(HttpHeaders.SET_COOKIE, clearCsrfCookie().toString());
        }
    }

    private void validateCsrfToken(HttpServletRequest request) {
        if (!authProperties.getCsrf().isEnabled() || !StringUtils.hasText(readRefreshToken(request))) {
            return;
        }

        AuthProperties.Csrf csrf = authProperties.getCsrf();
        String headerToken = request.getHeader(csrf.getHeaderName());
        String cookieToken = readCookie(request, csrf.getCookieName());

        if (!StringUtils.hasText(headerToken) || !StringUtils.hasText(cookieToken)
                || !MessageDigest.isEqual(
                        headerToken.getBytes(StandardCharsets.UTF_8),
                        cookieToken.getBytes(StandardCharsets.UTF_8))) {
            throw new InvalidCsrfTokenException();
        }
    }

    private String newCsrfToken() {
        return SecureTokenGenerator.randomUrlSafeToken(authProperties.getCsrf().getTokenBytes());
    }

    private String readRefreshToken(HttpServletRequest request) {
        return readCookie(request, authProperties.getCookie().getRefreshName());
    }

    private String readCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        return Arrays.stream(cookies)
                .filter(cookie -> cookieName.equals(cookie.getName()))
                .map(Cookie::getValue)
                .filter(StringUtils::hasText)
                .findFirst()
                .orElse(null);
    }
}
