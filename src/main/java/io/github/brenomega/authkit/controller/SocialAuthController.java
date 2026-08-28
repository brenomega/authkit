package io.github.brenomega.authkit.controller;

import java.time.Duration;
import java.util.Objects;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.github.brenomega.authkit.domain.social.dto.SocialAuthorizationResponse;
import io.github.brenomega.authkit.domain.social.dto.SocialCallbackResponse;
import io.github.brenomega.authkit.domain.social.dto.SocialLoginStartRequest;
import io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.response.ApiResponse;
import io.github.brenomega.authkit.service.SocialIdentityService;

/**
 * Adapts public social-login redirects and callbacks to browser session handling.
 * OIDC state, nonce, and PKCE guarantees remain in the service and provider-client
 * boundaries; only a completed login callback receives refresh and CSRF cookies.
 */
@RestController
@RequestMapping("/api/v1/auth/social")
public class SocialAuthController {
    private final SocialIdentityService service;
    private final AuthProperties properties;

    public SocialAuthController(SocialIdentityService service, AuthProperties properties) {
        this.service = service;
        this.properties = properties;
    }

    /** Starts an OIDC login transaction with consent bound to its state. */
    @PostMapping("/{providerKey}/start")
    public ApiResponse<SocialAuthorizationResponse> start(@PathVariable String providerKey,
            @RequestBody(required = false) SocialLoginStartRequest request) {
        return ApiResponse.success(service.startLogin(providerKey, request));
    }

    /** Consumes the callback transaction and establishes a session only for a login result. */
    @GetMapping("/{providerKey}/callback")
    public ResponseEntity<ApiResponse<SocialCallbackResponse>> callback(@PathVariable String providerKey,
            @RequestParam String state, @RequestParam String code) {
        var result = service.callback(providerKey, state, code);
        HttpHeaders headers = new HttpHeaders();
        if (StringUtils.hasText(result.refreshToken())) addSessionCookies(headers, result.refreshToken());
        return ResponseEntity.ok().headers(headers).body(ApiResponse.success(result.response()));
    }

@SuppressWarnings("null")
private void addSessionCookies(HttpHeaders headers, String refreshToken) {
        AuthProperties.Cookie cookie = Objects.requireNonNull(
                properties.getCookie(), "authkit.auth.cookie");
        AuthProperties.Csrf csrf = Objects.requireNonNull(
                properties.getCsrf(), "authkit.auth.csrf");
        String refreshName = Objects.requireNonNull(
                cookie.getRefreshName(), "authkit.auth.cookie.refresh-name");
        headers.add(HttpHeaders.SET_COOKIE, ResponseCookie.from(refreshName, refreshToken)
                .httpOnly(cookie.isHttpOnly()).secure(cookie.isSecure()).sameSite(cookie.getSameSite())
                .path(cookie.getPath()).maxAge(Duration.ofDays(properties.getToken().getRefreshTokenTtlDays()))
                .build().toString());
        if (csrf.isEnabled()) {
            String cookieName = Objects.requireNonNull(
                    csrf.getCookieName(), "authkit.auth.csrf.cookie-name");
            headers.add(HttpHeaders.SET_COOKIE, ResponseCookie.from(cookieName,
                            SecureTokenGenerator.randomUrlSafeToken(csrf.getTokenBytes()))
                    .httpOnly(false).secure(cookie.isSecure()).sameSite(cookie.getSameSite())
                    .path(csrf.getPath()).maxAge(Duration.ofDays(properties.getToken().getRefreshTokenTtlDays()))
                    .build().toString());
        }
    }
}
