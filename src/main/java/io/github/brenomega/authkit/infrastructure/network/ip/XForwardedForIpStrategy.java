package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

/**
 * IP resolution strategy using the {@code X-Forwarded-For} header with
 * trusted proxy depth enforcement (DT 3.2.20).
 *
 * <p>Unlike naive implementations that blindly trust the first (leftmost) IP
 * in the {@code X-Forwarded-For} chain, this strategy applies the
 * {@code trustedProxyDepth} algorithm to prevent IP spoofing:</p>
 *
 * <pre>
 * X-Forwarded-For: spoofed, real-client, proxy1, proxy2
 *                  ^^^^^^^^  ^^^^^^^^^^^  ^^^^^^  ^^^^^^
 *                  untrusted  client IP   trusted trusted
 *
 * With proxy-depth=2:
 *   index = length - proxyDepth - 1 = 4 - 2 - 1 = 1
 *   result = "real-client" ✓
 * </pre>
 *
 * <p>The rightmost IPs are appended by trusted infrastructure (reverse proxies
 * under our control). The leftmost IPs are user-controlled and potentially
 * spoofed. By counting backwards from the right by {@code proxyDepth}, we
 * select the IP that was inserted by the outermost trusted proxy — which is
 * the real client IP.</p>
 *
 * <p>This strategy has <strong>medium priority</strong> (order 200) in the
 * resolution chain, below Cloudflare but above the direct fallback.</p>
 *
 * <p>Enabled by default. Disable via:
 * {@code network.strategy.x-forwarded-for.enabled=false}</p>
 *
 * @see IpResolutionStrategy
 * @see NetworkIPResolver
 */
@Component
@ConditionalOnProperty(name = "network.strategy.x-forwarded-for.enabled", havingValue = "true", matchIfMissing = true)
public class XForwardedForIpStrategy implements IpResolutionStrategy {

    private static final Logger log = LoggerFactory.getLogger(XForwardedForIpStrategy.class);
    private static final String X_FORWARDED_FOR = "X-Forwarded-For";

    private final int proxyDepth;

    /**
     * Constructs the strategy with the configured trusted proxy depth.
     *
     * @param proxyDepth the number of trusted reverse proxies in front of
     *                   this application (DT 3.2.20). Default: 1.
     */
    public XForwardedForIpStrategy(@Value("${network.proxy-depth:1}") int proxyDepth) {
        this.proxyDepth = proxyDepth;
        log.info("XForwardedForIpStrategy initialized with trustedProxyDepth={} (DT 3.2.20)", proxyDepth);
    }

    /**
     * Resolves the client IP from the {@code X-Forwarded-For} header using
     * the trusted proxy depth algorithm (DT 3.2.20).
     *
     * <p>Selects the IP at index {@code length - proxyDepth - 1}, which is the
     * IP appended by the outermost trusted proxy (the real client). If the header
     * doesn't contain enough entries for the configured depth, the first IP is
     * returned as a safe fallback.</p>
     *
     * @param request the HTTP servlet request
     * @return the resolved client IP, or empty if the header is absent
     */
    @Override
    public Optional<String> resolveIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader(X_FORWARDED_FOR);
        if (xForwardedFor == null || xForwardedFor.isBlank()) {
            return Optional.empty();
        }

        String[] ips = xForwardedFor.split(",");
        for (int i = 0; i < ips.length; i++) {
            ips[i] = ips[i].trim();
        }

        // Apply trustedProxyDepth: select ips[length - proxyDepth - 1]
        int targetIndex = ips.length - proxyDepth - 1;

        if (targetIndex < 0) {
            // Not enough IPs for the configured depth — fail closed to prevent spoofing
            log.debug("X-Forwarded-For has {} entries but proxy-depth is {}. " +
                      "Failing closed to prevent IP spoofing (DT 3.2.20).", ips.length, proxyDepth);
            return Optional.empty();
        }

        return Optional.of(ips[targetIndex]);
    }

    /**
     * Returns 200 — medium priority in the resolution chain.
     *
     * @return 200
     */
    @Override
    public int getOrder() {
        return 200;
    }
}
