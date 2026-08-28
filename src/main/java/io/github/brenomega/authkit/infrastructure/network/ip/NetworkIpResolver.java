package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Comparator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Resolves the client address from the first applicable configured strategy.
 *
 * <p>Injects all available {@link IpResolutionStrategy} beans, sorts them by
 * {@link IpResolutionStrategy#getOrder()} ascending, and iterates through them
 * for each request. The first strategy that returns a non-empty result wins.</p>
 *
 * <p>Strategies are conditionally enabled via {@code application.yml}, allowing
 * the resolution chain to be adapted for any reverse proxy topology without
 * code changes. An invalid forwarded-header strategy yields no candidate and the
 * chain continues; it does not by itself reject the request. If every strategy is
 * empty, the socket peer address is the final fallback.</p>
 *
 * @see IpResolutionStrategy
 * @see io.github.brenomega.authkit.infrastructure.network.rateLimit.RateLimitingFilter
 */
@Component
public class NetworkIpResolver {

    private static final Logger log = LoggerFactory.getLogger(NetworkIpResolver.class);
    private final List<IpResolutionStrategy> strategies;

    /**
     * Creates a resolver whose strategies are fixed in ascending priority order.
     */
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

    /**
     * Returns the first strategy candidate or the direct peer address.
     *
     * @param request the active servlet request
     * @return the resolved client IP
     */
    public String resolveClientIp(HttpServletRequest request) {
        for (IpResolutionStrategy strategy : strategies) {
            var result = strategy.resolveIp(request);
            if (result.isPresent()) {
                return result.get();
            }
        }

        // Safety net — should never reach here if DirectIpStrategy is active
        return request.getRemoteAddr();
    }
}
