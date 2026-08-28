package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Selects a client address from {@code X-Forwarded-For} using configured proxy depth.
 * The index is counted from the trusted proxy end of the chain. A chain shorter
 * than the configured depth yields no candidate, preventing fallback to an
 * attacker-controlled leftmost value.
 */
@Component
@ConditionalOnProperty(name = "network.strategy.x-forwarded-for.enabled", havingValue = "true", matchIfMissing = true)
public class XForwardedForIpStrategy implements IpResolutionStrategy {

    private static final Logger log = LoggerFactory.getLogger(XForwardedForIpStrategy.class);
    private static final String X_FORWARDED_FOR = "X-Forwarded-For";

    private final int proxyDepth;

    public XForwardedForIpStrategy(@Value("${network.proxy-depth:1}") int proxyDepth) {
        this.proxyDepth = proxyDepth;
        log.info("XForwardedForIpStrategy initialized with trustedProxyDepth={} (DT 3.2.20)", proxyDepth);
    }

    /** Resolves the entry immediately before the configured number of trusted proxies. */
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

        int targetIndex = ips.length - proxyDepth;

        if (targetIndex < 0) {

            log.debug("X-Forwarded-For has {} entries but proxy-depth is {}. " +
                      "Failing closed to prevent IP spoofing (DT 3.2.20).", ips.length, proxyDepth);
            return Optional.empty();
        }

        return Optional.of(ips[targetIndex]);
    }

    @Override
    public int getOrder() {
        return 200;
    }
}
