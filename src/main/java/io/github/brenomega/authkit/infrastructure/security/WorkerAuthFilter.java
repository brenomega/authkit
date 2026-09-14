package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.lang.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.brenomega.authkit.infrastructure.network.origin.WorkerTrustedOriginProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Authenticates internal worker requests with origin restriction and a shared secret.
 * The request must originate from {@link WorkerTrustedOriginProvider} and present either
 * the current or an explicitly configured previous token. Comparison is constant
 * time; use of a previous token is accepted for rotation but recorded by metrics.
 */
@Component
public class WorkerAuthFilter extends OncePerRequestFilter {

    private final String workerToken;
    private final List<String> previousWorkerTokens;
    private final WorkerTrustedOriginProvider trustedOriginProvider;
    private final MeterRegistry meterRegistry;
    private static final String HEADER_NAME = "X-Worker-Token";

    @SuppressWarnings("null")
    public WorkerAuthFilter(@Value("${app.security.worker-token}") String workerToken,
                            @Value("${app.security.worker-previous-tokens:}") String previousWorkerTokens,
                            WorkerTrustedOriginProvider trustedOriginProvider,
                            MeterRegistry meterRegistry) {
        this.workerToken = workerToken;
        this.previousWorkerTokens = Arrays.stream(previousWorkerTokens.split(","))
                .map(String::trim)
                .filter(token -> !token.isBlank())
                .toList();
        this.trustedOriginProvider = trustedOriginProvider;
        this.meterRegistry = meterRegistry;
    }

    /** Limits worker authentication to internal endpoints and Prometheus metrics. */
    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/v1/internal/")
                && !"/actuator/prometheus".equals(path);
    }

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String tokenHeader = request.getHeader(HEADER_NAME);

        if (!trustedOriginProvider.isTrusted(request.getRemoteAddr())) {
            meterRegistry.counter("security.worker_auth.denied", "reason", "untrusted_origin").increment();
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        if (tokenHeader == null || tokenHeader.isBlank()) {
            meterRegistry.counter("security.worker_auth.denied", "reason", "missing_token").increment();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        if (constantTimeEquals(tokenHeader, workerToken)) {

            var workerAuth = new UsernamePasswordAuthenticationToken(
                    "internal-worker",
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_WORKER"))
            );
            SecurityContextHolder.getContext().setAuthentication(workerAuth);
        } else if (previousWorkerTokens.stream().anyMatch(previous -> constantTimeEquals(tokenHeader, previous))) {
            meterRegistry.counter("security.worker_auth.previous_token_used").increment();
            var workerAuth = new UsernamePasswordAuthenticationToken(
                    "internal-worker",
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_WORKER"))
            );
            SecurityContextHolder.getContext().setAuthentication(workerAuth);
        } else {
            meterRegistry.counter("security.worker_auth.denied", "reason", "invalid_token").increment();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean constantTimeEquals(String candidate, String expected) {
        if (candidate == null || expected == null) {
            return false;
        }
        return MessageDigest.isEqual(
                candidate.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8));
    }
}
