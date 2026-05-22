package io.github.brenomega.authkit.infrastructure.security;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Type-safe runtime configuration for AuthKit authentication surfaces.
 *
 * <p>These settings are intentionally externalized because token lifetimes,
 * cookie posture, issuer identity, and public frontend URLs vary between
 * deployments while the service remains stateless.</p>
 */
@Validated
@ConfigurationProperties(prefix = "authkit.auth")
public class AuthProperties {

    @Valid
    private Token token = new Token();

    @Valid
    private Cookie cookie = new Cookie();

    @Valid
    private Jwt jwt = new Jwt();

    @Valid
    private Frontend frontend = new Frontend();

    public Token getToken() {
        return token;
    }

    public void setToken(Token token) {
        this.token = token;
    }

    public Cookie getCookie() {
        return cookie;
    }

    public void setCookie(Cookie cookie) {
        this.cookie = cookie;
    }

    public Jwt getJwt() {
        return jwt;
    }

    public void setJwt(Jwt jwt) {
        this.jwt = jwt;
    }

    public Frontend getFrontend() {
        return frontend;
    }

    public void setFrontend(Frontend frontend) {
        this.frontend = frontend;
    }

    public static class Token {

        @Min(60)
        private long accessTokenTtlSeconds = 900;

        @Min(1)
        private long refreshTokenTtlDays = 7;

        @Min(1)
        private long recoveryTokenTtlMinutes = 15;

        public long getAccessTokenTtlSeconds() {
            return accessTokenTtlSeconds;
        }

        public void setAccessTokenTtlSeconds(long accessTokenTtlSeconds) {
            this.accessTokenTtlSeconds = accessTokenTtlSeconds;
        }

        public long getRefreshTokenTtlDays() {
            return refreshTokenTtlDays;
        }

        public void setRefreshTokenTtlDays(long refreshTokenTtlDays) {
            this.refreshTokenTtlDays = refreshTokenTtlDays;
        }

        public long getRecoveryTokenTtlMinutes() {
            return recoveryTokenTtlMinutes;
        }

        public void setRecoveryTokenTtlMinutes(long recoveryTokenTtlMinutes) {
            this.recoveryTokenTtlMinutes = recoveryTokenTtlMinutes;
        }
    }

    public static class Cookie {

        @NotBlank
        private String refreshName = "Refresh-Token";

        @NotBlank
        @Pattern(regexp = "/.*")
        private String path = "/api/v1/auth";

        private boolean httpOnly = true;

        private boolean secure = true;

        @NotBlank
        @Pattern(regexp = "Strict|Lax|None")
        private String sameSite = "Strict";

        public String getRefreshName() {
            return refreshName;
        }

        public void setRefreshName(String refreshName) {
            this.refreshName = refreshName;
        }

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public boolean isHttpOnly() {
            return httpOnly;
        }

        public void setHttpOnly(boolean httpOnly) {
            this.httpOnly = httpOnly;
        }

        public boolean isSecure() {
            return secure;
        }

        public void setSecure(boolean secure) {
            this.secure = secure;
        }

        public String getSameSite() {
            return sameSite;
        }

        public void setSameSite(String sameSite) {
            this.sameSite = sameSite;
        }

        @AssertTrue(message = "secure must be true when SameSite=None")
        public boolean isSecureWhenSameSiteNone() {
            return !"None".equals(sameSite) || secure;
        }
    }

    public static class Jwt {

        @NotBlank
        private String issuer = "authkit";

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }
    }

    public static class Frontend {

        @NotBlank
        @Pattern(regexp = "https?://.+")
        private String activationUrl = "https://authkit.io/activate";

        @NotBlank
        @Pattern(regexp = "https?://.+")
        private String passwordResetUrl = "https://frontend.url/reset-password";

        public String getActivationUrl() {
            return activationUrl;
        }

        public void setActivationUrl(String activationUrl) {
            this.activationUrl = activationUrl;
        }

        public String getPasswordResetUrl() {
            return passwordResetUrl;
        }

        public void setPasswordResetUrl(String passwordResetUrl) {
            this.passwordResetUrl = passwordResetUrl;
        }
    }
}
