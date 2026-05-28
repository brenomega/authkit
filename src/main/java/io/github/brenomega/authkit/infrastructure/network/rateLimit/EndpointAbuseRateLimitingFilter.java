package io.github.brenomega.authkit.infrastructure.network.rateLimit;

import java.io.IOException;
import java.util.List;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.brenomega.authkit.infrastructure.network.ip.NetworkIpResolver;
import io.github.brenomega.authkit.exception.RateLimitExceededException;
import io.github.brenomega.authkit.infrastructure.security.AbuseRateLimitPolicy;
import io.github.brenomega.authkit.infrastructure.security.AbuseThrottleService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class EndpointAbuseRateLimitingFilter extends OncePerRequestFilter {

    private final NetworkIpResolver ipResolver;
    private final AbuseThrottleService abuseThrottleService;

    public EndpointAbuseRateLimitingFilter(NetworkIpResolver ipResolver,
                                           AbuseThrottleService abuseThrottleService) {
        this.ipResolver = ipResolver;
        this.abuseThrottleService = abuseThrottleService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        List<AbuseRateLimitPolicy> policies = policiesFor(request.getMethod(), request.getRequestURI());
        if (!policies.isEmpty()) {
            String clientIp = resolvedClientIp(request);
            String userAgent = request.getHeader("User-Agent");
            try {
                for (AbuseRateLimitPolicy policy : policies) {
                    abuseThrottleService.check(policy, "ip:" + clientIp);
                    abuseThrottleService.check(policy, "ua:" + clientIp + ':' + (userAgent == null ? "unknown" : userAgent));
                }
            } catch (RateLimitExceededException ex) {
                sendRateLimitResponse(response);
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private String resolvedClientIp(HttpServletRequest request) {
        Object existing = request.getAttribute("X-Resolved-Client-IP");
        return existing instanceof String value && !value.isBlank()
                ? value
                : ipResolver.resolveClientIp(request);
    }

    private List<AbuseRateLimitPolicy> policiesFor(String method, String path) {
        if ("POST".equals(method) && "/api/v1/auth/login".equals(path)) {
            return List.of(AbuseRateLimitPolicy.LOGIN_ENDPOINT_IP, AbuseRateLimitPolicy.LOGIN_ENDPOINT_DEVICE);
        }
        if ("POST".equals(method) && "/api/v1/auth/mfa/verify-login".equals(path)) {
            return List.of(AbuseRateLimitPolicy.MFA_VERIFY_IP);
        }
        if ("POST".equals(method) && path.startsWith("/api/v1/auth/passkeys/")) {
            return List.of(AbuseRateLimitPolicy.PASSKEY_ASSERTION_IP, AbuseRateLimitPolicy.PASSKEY_ASSERTION_DEVICE);
        }
        if ("POST".equals(method) && "/api/v1/auth/register".equals(path)) {
            return List.of(AbuseRateLimitPolicy.REGISTRATION_IP);
        }
        if ("POST".equals(method) && path.startsWith("/api/v1/auth/email-confirmation/")) {
            return List.of(AbuseRateLimitPolicy.EMAIL_CONFIRMATION_RESEND_IP);
        }
        if ("POST".equals(method) && "/api/v1/auth/password-recovery/request".equals(path)) {
            return List.of(AbuseRateLimitPolicy.PASSWORD_RECOVERY_IP);
        }
        if ("POST".equals(method) && "/api/v1/auth/password-recovery/reset".equals(path)) {
            return List.of(AbuseRateLimitPolicy.PASSWORD_RESET_IP);
        }
        if ("POST".equals(method) && "/api/v1/auth/refresh".equals(path)) {
            return List.of(AbuseRateLimitPolicy.REFRESH_IP);
        }
        if ("POST".equals(method) && "/api/v1/oauth2/authorize".equals(path)) {
            return List.of(AbuseRateLimitPolicy.OAUTH_AUTHORIZE_IP);
        }
        if ("POST".equals(method)
                && ("/oauth2/token".equals(path)
                || "/oauth2/revoke".equals(path)
                || "/oauth2/introspect".equals(path))) {
            return List.of(AbuseRateLimitPolicy.OAUTH_TOKEN_IP);
        }
        if (path.startsWith("/api/v1/admin/")
                && ("POST".equals(method) || "PATCH".equals(method) || "DELETE".equals(method))) {
            return List.of(AbuseRateLimitPolicy.ADMIN_WRITE_TENANT);
        }
        if (path.startsWith("/api/v1/users/me")
                && ("POST".equals(method) || "PATCH".equals(method) || "DELETE".equals(method))) {
            return List.of(AbuseRateLimitPolicy.PROFILE_WRITE_USER);
        }
        return List.of();
    }

    private void sendRateLimitResponse(HttpServletResponse response) throws IOException {
        response.setStatus(429);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("""
                {"errors":["Too many requests"]}
                """);
    }
}
