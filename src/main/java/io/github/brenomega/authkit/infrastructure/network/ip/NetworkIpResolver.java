package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Comparator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Selects the first available client-IP signal from the configured strategy chain.
 * Header-based strategies rely on deployment perimeter and proxy-depth configuration
 * for authenticity; the servlet peer address is the final fallback.
 */
@Component
public class NetworkIpResolver {

    private static final Logger log = LoggerFactory.getLogger(NetworkIpResolver.class);
    private final List<IpResolutionStrategy> strategies;

    @SuppressWarnings("null")
    public NetworkIpResolver(List<IpResolutionStrategy> strategies) {
        this.strategies = strategies.stream()
                .sorted(Comparator.comparingInt(IpResolutionStrategy::getOrder))
                .toList();

        log.info("NetworkIPResolver initialized with {} strategies: {} (DT 3.2.17)",
                 this.strategies.size(),
                 this.strategies.stream()
                         .map(s -> s.getClass().getSimpleName() + "(order=" + s.getOrder() + ")")
                         .toList());
    }

    /** Returns the highest-precedence candidate, or the direct peer address. */
    public String resolveClientIp(HttpServletRequest request) {
        for (IpResolutionStrategy strategy : strategies) {
            var result = strategy.resolveIp(request);
            if (result.isPresent()) {
                return result.get();
            }
        }

        return request.getRemoteAddr();
    }
}
