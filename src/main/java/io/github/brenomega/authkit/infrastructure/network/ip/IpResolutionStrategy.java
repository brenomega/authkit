package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Resolves a candidate client address from one trusted request signal.
 *
 * <p>Implementations extract the client IP from specific headers or connection
 * metadata, forming a prioritized chain orchestrated by {@link NetworkIpResolver}.
 * Each strategy returns an {@link Optional} — empty if the strategy's header is
 * absent or invalid, present if a valid IP was extracted.</p>
 *
 * <p>Strategies are ordered by {@link #getOrder()}: lower values have higher
 * priority. The orchestrator iterates through strategies in ascending order
 * and returns the first non-empty result.</p>
 *
 * <p>An empty result means that the signal is absent or unusable and allows the
 * resolver to try the next strategy; it is not itself a request rejection.</p>
 *
 * @see NetworkIpResolver
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
     * Returns the priority order of this strategy.
     *
     * @return the priority; lower values are evaluated first
     */
    int getOrder();
}
