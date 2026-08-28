package io.github.brenomega.authkit.infrastructure.network.origin;

import io.github.brenomega.authkit.infrastructure.network.ip.IpMasker;
import io.github.brenomega.authkit.response.RequestContext;
import java.io.IOException;
import java.time.Instant;

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
 * Enforces the network-origin allowlist before protected application processing.
 * Decisions use the direct servlet peer address rather than forwarded headers. The
 * sole bypass is the local health probe for the exact health endpoint; rejected
 * addresses are precision-masked in logs.
 */
@Component
public class OriginFirewallFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(OriginFirewallFilter.class);
    private final TrustedOriginProvider trustedOriginProvider;
    private final MeterRegistry meterRegistry;

    public OriginFirewallFilter(TrustedOriginProvider trustedOriginProvider, MeterRegistry meterRegistry) {
        this.trustedOriginProvider = trustedOriginProvider;
        this.meterRegistry = meterRegistry;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String remoteIp = request.getRemoteAddr();

        if (isLocalHealthCheck(request, remoteIp)) {
            filterChain.doFilter(request, response);
            return;
        }

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
                "{\"errors\":[\"Invalid Origin\"],"
                    + "\"timestamp\":\"%s\",\"code\":\"invalid_origin\","
                    + "\"requestId\":\"%s\"}",
                Instant.now(), RequestContext.currentRequestId()
            );
            response.getWriter().write(jsonResponse);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean isLocalHealthCheck(HttpServletRequest request, String remoteIp) {
        boolean loopback = "127.0.0.1".equals(remoteIp)
                || "::1".equals(remoteIp)
                || "0:0:0:0:0:0:0:1".equals(remoteIp);
        return loopback
                && "GET".equals(request.getMethod())
                && "/actuator/health".equals(request.getRequestURI());
    }
}
