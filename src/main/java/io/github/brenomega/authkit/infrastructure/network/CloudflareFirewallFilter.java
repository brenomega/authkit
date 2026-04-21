package io.github.brenomega.authkit.infrastructure.network;

import java.io.IOException;
import java.util.List;

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

    private final List<IpAddressMatcher> cloudflareRanges = List.of(
            new IpAddressMatcher("173.245.48.0/20"),
            new IpAddressMatcher("103.21.244.0/22"),
            new IpAddressMatcher("103.22.200.0/22"),
            new IpAddressMatcher("103.31.4.0/22"),
            new IpAddressMatcher("141.101.64.0/18"),
            new IpAddressMatcher("108.162.192.0/18"),
            new IpAddressMatcher("190.93.240.0/20"),
            new IpAddressMatcher("188.114.96.0/20"),
            new IpAddressMatcher("197.234.240.0/22"),
            new IpAddressMatcher("198.41.128.0/17"),
            new IpAddressMatcher("162.158.0.0/15"),
            new IpAddressMatcher("104.16.0.0/13"),
            new IpAddressMatcher("104.24.0.0/14"),
            new IpAddressMatcher("172.64.0.0/13"),
            new IpAddressMatcher("131.0.72.0/22"),
            // Localhost ranges explicitly included for testing bounds
            new IpAddressMatcher("127.0.0.1/32"),
            new IpAddressMatcher("0:0:0:0:0:0:0:1/128")
    );

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String remoteIp = request.getRemoteAddr();
        
        boolean isTrustedOrigin = cloudflareRanges.stream()
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
