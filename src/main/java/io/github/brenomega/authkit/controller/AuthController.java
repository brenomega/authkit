package io.github.brenomega.authkit.controller;

import java.time.Duration;
import java.util.Arrays;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.web.bind.annotation.RequestParam;
import io.github.brenomega.authkit.domain.user.dto.LoginRequest;
import io.github.brenomega.authkit.domain.user.dto.LoginResponse;
import io.github.brenomega.authkit.domain.user.dto.RegisterRequest;
import io.github.brenomega.authkit.domain.user.dto.RegisterResponse;
import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.AuthService;
import io.github.brenomega.authkit.service.RegistrationService;
import io.github.brenomega.authkit.domain.user.dto.PasswordRecoveryRequest;
import io.github.brenomega.authkit.domain.user.dto.PasswordResetRequest;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.service.PasswordRecoveryService;
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
    private final AuthProperties authProperties;

    public AuthController(
            RegistrationService registrationService,
            AuthService authService,
            PasswordRecoveryService recoveryService,
            AuthProperties authProperties) {
        this.registrationService = registrationService;
        this.authService = authService;
        this.recoveryService = recoveryService;
        this.authProperties = authProperties;
    }

    /**
     * Executes the secure identity negotiation lifecycle (RF 2.1.2).
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest request) {
        AuthService.LoginResult result = authService.login(request);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie(result.refreshToken()).toString())
                .body(ApiResponse.success(result.response()));
    }

    /**
     * Rotates the refresh token and issues a fresh access token (RF 2.1.5, DT 3.2.4).
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<LoginResponse>> refresh(HttpServletRequest request) {

        AuthService.LoginResult result = authService.refresh(readRefreshToken(request));

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie(result.refreshToken()).toString())
                .body(ApiResponse.success(result.response()));
    }

    /**
     * Revokes the current refresh-token-backed session and clears the cookie (RF 2.1.5).
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<String>> logout(HttpServletRequest request) {

        authService.logout(readRefreshToken(request));

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, clearRefreshCookie().toString())
                .body(ApiResponse.success("Logged out successfully."));
    }

    /**
     * Registers a new user account (RF 2.1.1).
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<RegisterResponse>> register(
            @Valid @RequestBody RegisterRequest request) {
        
        User user = registrationService.registerUser(request);
        
        RegisterResponse responseDto = new RegisterResponse(
                user.getId().toString(),
                user.getEmail(),
                user.getTenantId().toString()
        );
        
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(responseDto));
    }

    /**
     * Confirms a registered user's email address (RF 2.1.7).
     */
    @PostMapping("/email-confirmation/confirm")
    public ResponseEntity<ApiResponse<String>> confirmEmail(@RequestParam String token) {
        registrationService.confirmEmail(token);
        return ResponseEntity.ok(ApiResponse.success("Email confirmed successfully."));
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

    private String readRefreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        String refreshName = authProperties.getCookie().getRefreshName();
        return Arrays.stream(cookies)
                .filter(cookie -> refreshName.equals(cookie.getName()))
                .map(Cookie::getValue)
                .filter(StringUtils::hasText)
                .findFirst()
                .orElse(null);
    }
}
