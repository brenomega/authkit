package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Comparator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Orchestrator for client IP resolution using the Chain of Responsibility pattern (DT 3.2.17, DT 3.2.20).
 *
 * <p>Injects all available {@link IpResolutionStrategy} beans, sorts them by
 * {@link IpResolutionStrategy#getOrder()} ascending, and iterates through them
 * for each request. The first strategy that returns a non-empty result wins.</p>
 *
 * <h3>Default Resolution Order</h3>
 * <ol>
 *   <li>{@link CloudflareIpStrategy} (order 100) — {@code CF-Connecting-IP}</li>
 *   <li>{@link XForwardedForIpStrategy} (order 200) — {@code X-Forwarded-For} with trustedProxyDepth</li>
 *   <li>{@link DirectIpStrategy} (order 300) — {@code request.getRemoteAddr()}</li>
 * </ol>
 *
 * <p>Strategies are conditionally enabled via {@code application.yml}, allowing
 * the resolution chain to be adapted for any reverse proxy topology without
 * code changes.</p>
 *
 * <p>If all strategies return empty (shouldn't happen with {@code DirectIpStrategy}),
 * falls back to {@code request.getRemoteAddr()} as a safety net.</p>
 *
 * @see IpResolutionStrategy
 * @see RateLimitingFilter
 */
@Component
public class NetworkIpResolver {

    private static final Logger log = LoggerFactory.getLogger(NetworkIpResolver.class);
    private final List<IpResolutionStrategy> strategies;

    /**
     * Constructs the resolver with all available IP resolution strategies.
     *
     * @param strategies the injected strategies, sorted by order at construction time
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
     * Resolves the real client IP by iterating through the strategy chain (DT 3.2.17, DT 3.2.20).
     *
     * <p>Returns the first non-empty result from the ordered strategy chain.
     * If no strategy produces a result, falls back to the direct remote address.</p>
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
