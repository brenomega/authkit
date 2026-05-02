package io.github.brenomega.authkit.infrastructure.network;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Strategy interface for resolving the real client IP from an HTTP request (DT 3.2.17, DT 3.2.20).
 *
 * <p>Implementations extract the client IP from specific headers or connection
 * metadata, forming a prioritized chain orchestrated by {@link NetworkIPResolver}.
 * Each strategy returns an {@link Optional} — empty if the strategy's header is
 * absent or invalid, present if a valid IP was extracted.</p>
 *
 * <p>Strategies are ordered by {@link #getOrder()}: lower values have higher
 * priority. The orchestrator iterates through strategies in ascending order
 * and returns the first non-empty result.</p>
 *
 * <h3>Available Strategies</h3>
 * <ul>
 *   <li>{@link CloudflareIpStrategy} — Order 100 (highest priority)</li>
 *   <li>{@link XForwardedForIpStrategy} — Order 200 (with trustedProxyDepth)</li>
 *   <li>{@link DirectIpStrategy} — Order 300 (fallback)</li>
 * </ul>
 *
 * @see NetworkIPResolver
 */
public interface IpResolutionStrategy {

    /**
     * Attempts to resolve the client IP from the given request.
     *
     * @param request the HTTP servlet request
     * @return the resolved IP, or empty if this strategy cannot determine the IP
     */
    Optional<String> resolveIp(HttpServletRequest request);

    /**
     * Returns the priority order of this strategy. Lower values = higher priority.
     *
     * @return the priority order
     */
    int getOrder();
}
