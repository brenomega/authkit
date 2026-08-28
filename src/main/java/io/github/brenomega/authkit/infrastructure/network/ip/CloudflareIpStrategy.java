package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Optional;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

@Component
@ConditionalOnProperty(name = "network.strategy.cloudflare.enabled", havingValue = "true", matchIfMissing = true)
public class CloudflareIpStrategy implements IpResolutionStrategy {

    private static final String CF_CONNECTING_IP = "CF-Connecting-IP";

    @Override
    public Optional<String> resolveIp(HttpServletRequest request) {
        String cfIp = request.getHeader(CF_CONNECTING_IP);
        if (cfIp != null && !cfIp.isBlank()) {
            return Optional.of(cfIp.split(",")[0].trim());
        }
        return Optional.empty();
    }

    @Override
    public int getOrder() {
        return 100;
    }
}
