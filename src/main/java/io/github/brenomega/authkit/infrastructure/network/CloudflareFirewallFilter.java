package io.github.brenomega.authkit.infrastructure.network;

import java.io.IOException;
import java.util.List;

import org.springframework.lang.NonNull;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Validates active TCP stream bounds against defined Edge protections (DT 3.2.19).
 *
 * <p>Prevents architecture bypass vulnerabilities where malicious actors target
 * explicit Backend IPs directly instead of passing through Cloudflare constraints.</p>
 */
@Component
public class CloudflareFirewallFilter extends OncePerRequestFilter {

    private final List<IpAddressMatcher> cloudflareMatchers;

    public CloudflareFirewallFilter(NetworkSecurityProperties properties) {
        this.cloudflareMatchers = properties.getEffectiveRanges().stream()
                .map(IpAddressMatcher::new)
                .toList();
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String remoteIp = request.getRemoteAddr();
        
        boolean isTrustedOrigin = cloudflareMatchers.stream()
                .anyMatch(matcher -> matcher.matches(remoteIp));

        if (!isTrustedOrigin) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            // Naked string bypasses standard API envelopes precisely to stop layer profiling
            response.getWriter().write("Forbidden: Invalid Origin");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
