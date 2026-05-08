package io.github.brenomega.authkit.infrastructure.network.origin;

/**
 * Strategy interface for origin validation in the firewall layer (DT 3.2.19).
 *
 * <p>Decouples the {@link OriginFirewallFilter} from any specific edge provider
 * (Cloudflare, AWS API Gateway, Nginx, etc.), enabling proxy-agnostic origin
 * validation driven by configuration rather than code.</p>
 *
 * <p>Implementations determine whether a given TCP source IP belongs to a
 * trusted reverse proxy or edge network. Untrusted origins are rejected
 * at the filter level before any application logic executes.</p>
 *
 * @see ConfiguredOriginsProvider
 * @see OriginFirewallFilter
 */
public interface TrustedOriginProvider {

    /**
     * Evaluates whether the given IP address belongs to a trusted origin.
     *
     * @param ip the remote IP address to validate (IPv4 or IPv6)
     * @return {@code true} if the IP matches a trusted CIDR range
     */
    boolean isTrusted(String ip);
}
