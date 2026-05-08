package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Optional;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

/**
 * IP resolution strategy for Cloudflare edge networks (DT 3.2.17).
 *
 * <p>Extracts the client IP from the {@code CF-Connecting-IP} header, which is
 * set by Cloudflare's reverse proxy before forwarding requests to the origin.
 * This header contains a single, authoritative IP and is not user-spoofable
 * when Cloudflare is properly configured as the sole entry point.</p>
 *
 * <p>This strategy has the <strong>highest priority</strong> (order 100) in the
 * resolution chain because Cloudflare's header is the most trustworthy source
 * when available.</p>
 *
 * <p>Enabled by default. Disable via:
 * {@code network.strategy.cloudflare.enabled=false}</p>
 *
 * @see IpResolutionStrategy
 * @see NetworkIPResolver
 */
@Component
@ConditionalOnProperty(name = "network.strategy.cloudflare.enabled", havingValue = "true", matchIfMissing = true)
public class CloudflareIpStrategy implements IpResolutionStrategy {

    private static final String CF_CONNECTING_IP = "CF-Connecting-IP";

    /**
     * Extracts the client IP from the {@code CF-Connecting-IP} header.
     *
     * @param request the HTTP servlet request
     * @return the Cloudflare-provided client IP, or empty if the header is absent
     */
    @Override
    public Optional<String> resolveIp(HttpServletRequest request) {
        String cfIp = request.getHeader(CF_CONNECTING_IP);
        if (cfIp != null && !cfIp.isBlank()) {
            return Optional.of(cfIp.split(",")[0].trim());
        }
        return Optional.empty();
    }

    /**
     * Returns 100 — highest priority in the resolution chain.
     *
     * @return 100
     */
    @Override
    public int getOrder() {
        return 100;
    }
}
