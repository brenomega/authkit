package io.github.brenomega.authkit.infrastructure.network;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Reverse-proxy-agnostic origin firewall filter (DT 3.2.19).
 *
 * <p>Validates that inbound TCP connections originate from a trusted reverse
 * proxy or edge network by delegating to a {@link TrustedOriginProvider}.
 * Requests from untrusted origins are rejected with HTTP 403 before any
 * application logic executes.</p>
 *
 * <p>This filter is positioned first in the Spring Security filter chain
 * (before {@code DisableEncodeUrlFilter}) to ensure that architecture-bypass
 * attacks — where malicious actors target backend IPs directly — are blocked
 * at the earliest possible point.</p>
 *
 * <p>The implementation is fully decoupled from any specific edge provider
 * (Cloudflare, AWS API Gateway, Nginx, etc.). The trusted CIDR ranges are
 * configured via {@code network.security.trusted-origins.ranges} in
 * {@code application.yml}.</p>
 *
 * @see TrustedOriginProvider
 * @see ConfiguredOriginsProvider
 * @see NetworkSecurityProperties
 */
@Component
public class OriginFirewallFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(OriginFirewallFilter.class);
    private final TrustedOriginProvider trustedOriginProvider;

    /**
     * Constructs the filter with the injected origin validation strategy.
     *
     * @param trustedOriginProvider the strategy for evaluating trusted origins (DT 3.2.19)
     */
    public OriginFirewallFilter(TrustedOriginProvider trustedOriginProvider) {
        this.trustedOriginProvider = trustedOriginProvider;
    }

    /**
     * Validates the request's remote address against trusted origin CIDR ranges (DT 3.2.19).
     *
     * <p>If the origin is not trusted, the request is immediately rejected with
     * HTTP 403 and a minimal response body to prevent layer profiling.</p>
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String remoteIp = request.getRemoteAddr();

        if (!trustedOriginProvider.isTrusted(remoteIp)) {
            log.warn("Origin rejected: untrusted remote IP {} attempted to access {} {} (DT 3.2.19)",
                     remoteIp, request.getMethod(), request.getRequestURI());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            // Naked string bypasses standard API envelopes precisely to stop layer profiling
            response.getWriter().write("Forbidden: Invalid Origin");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
