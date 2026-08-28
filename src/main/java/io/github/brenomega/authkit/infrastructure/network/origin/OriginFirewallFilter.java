package io.github.brenomega.authkit.infrastructure.network.origin;

import io.github.brenomega.authkit.infrastructure.network.config.NetworkSecurityProperties;
import io.github.brenomega.authkit.infrastructure.network.ip.IpMasker;
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

import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.MDC;

/**
 * Rejects connections whose TCP peer is outside configured edge CIDRs.
 *
 * <p>Validates that inbound TCP connections originate from a trusted reverse
 * proxy or edge network by delegating to a {@link TrustedOriginProvider}.
 * Requests from untrusted origins are rejected with HTTP 403 before any
 * application logic executes.</p>
 *
 * <p>The decision uses {@link HttpServletRequest#getRemoteAddr()}, never a
 * forwarded header, and runs before application authentication. It protects a
 * deployment only when the network perimeter prevents untrusted peers from
 * choosing that socket address.</p>
 *
 * @see TrustedOriginProvider
 * @see ConfiguredOriginsProvider
 * @see NetworkSecurityProperties
 */
@Component
public class OriginFirewallFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(OriginFirewallFilter.class);
    private final TrustedOriginProvider trustedOriginProvider;
    private final MeterRegistry meterRegistry;

    /**
     * Constructs the filter with the injected origin validation strategy.
     *
     * @param trustedOriginProvider the strategy for evaluating trusted origins (DT 3.2.19)
     * @param meterRegistry the meter registry for tracking dropped connections
     */
    public OriginFirewallFilter(TrustedOriginProvider trustedOriginProvider, MeterRegistry meterRegistry) {
        this.trustedOriginProvider = trustedOriginProvider;
        this.meterRegistry = meterRegistry;
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
            meterRegistry.counter("firewall.origin.rejected").increment();
            String traceId = request.getHeader("CF-RAY");
            if (traceId != null) {
                MDC.put("traceId", traceId);
            }
            try {
                log.warn("Origin rejected: untrusted remote IP {} attempted to access {} {} (DT 3.2.19)",
                         IpMasker.mask(remoteIp), request.getMethod(), request.getRequestURI());
            } finally {
                MDC.remove("traceId");
            }
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            String jsonResponse = String.format(
                "{\"timestamp\":\"%s\",\"status\":403,\"error\":\"Forbidden\",\"message\":\"Invalid Origin\"}",
                java.time.Instant.now().toString()
            );
            response.getWriter().write(jsonResponse);
            return;
        }

        filterChain.doFilter(request, response);
    }
}
