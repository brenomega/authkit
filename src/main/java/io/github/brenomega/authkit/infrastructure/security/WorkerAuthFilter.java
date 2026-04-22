package io.github.brenomega.authkit.infrastructure.security;

import java.io.IOException;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter that authenticates internal backend workers via a shared secret (DT 3.2.11).
 *
 * <p>It sits in the filter chain after the Bearer token validation and checks for
 * a specific worker header (e.g. X-Worker-Token). If valid, it assigns the
 * ROLE_WORKER authority.</p>
 */
@Component
public class WorkerAuthFilter extends OncePerRequestFilter {

    private final String workerToken;
    private static final String HEADER_NAME = "X-Worker-Token";

    public WorkerAuthFilter(@Value("${app.security.worker-token:fallback-worker-secret-token}") String workerToken) {
        this.workerToken = workerToken;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String tokenHeader = request.getHeader(HEADER_NAME);

        if (tokenHeader != null && tokenHeader.equals(workerToken)) {
            // Apply Worker Role
            var workerAuth = new UsernamePasswordAuthenticationToken(
                    "internal-worker",
                    null,
                    List.of(new SimpleGrantedAuthority("ROLE_WORKER"))
            );
            SecurityContextHolder.getContext().setAuthentication(workerAuth);
        }

        filterChain.doFilter(request, response);
    }
}
