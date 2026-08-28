package io.github.brenomega.authkit.infrastructure.network.ip;

import java.util.Optional;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Resolves a candidate client address from one trusted network topology signal.
 * Implementations return empty when their signal is absent or structurally unsafe;
 * lower numeric order takes precedence in {@link NetworkIpResolver}.
 */
public interface IpResolutionStrategy {

    /** Returns a candidate address, without implying that the address is syntactically normalized. */
    Optional<String> resolveIp(HttpServletRequest request);

    /** Returns precedence within the resolver chain; lower values run first. */
    int getOrder();
}
