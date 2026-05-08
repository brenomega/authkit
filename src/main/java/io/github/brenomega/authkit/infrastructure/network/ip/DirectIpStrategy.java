package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Optional;

import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Fallback IP resolution strategy using the direct TCP connection address (DT 3.2.20).
 *
 * <p>Returns {@code request.getRemoteAddr()} — the IP address of the direct
 * TCP connection to this server. This is always available and serves as the
 * guaranteed last-resort fallback in the resolution chain.</p>
 *
 * <p>This strategy has the <strong>lowest priority</strong> (order 300) and
 * is always active (no conditional property). It ensures that
 * {@link NetworkIPResolver} always returns a valid IP.</p>
 *
 * @see IpResolutionStrategy
 * @see NetworkIPResolver
 */
@Component
public class DirectIpStrategy implements IpResolutionStrategy {

    /**
     * Returns the direct TCP source IP from the servlet request.
     *
     * @param request the HTTP servlet request
     * @return the remote address (always present)
     */
    @Override
    public Optional<String> resolveIp(HttpServletRequest request) {
        return Optional.ofNullable(request.getRemoteAddr());
    }

    /**
     * Returns 300 — lowest priority (guaranteed fallback).
     *
     * @return 300
     */
    @Override
    public int getOrder() {
        return 300;
    }
}
