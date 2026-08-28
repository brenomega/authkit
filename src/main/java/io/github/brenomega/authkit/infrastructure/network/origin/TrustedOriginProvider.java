package io.github.brenomega.authkit.infrastructure.network.origin;

/**
 * Determines whether a TCP peer belongs to a configured trusted edge network.
 *
 * <p>Decouples the {@link OriginFirewallFilter} from any specific edge provider
 * (Cloudflare, AWS API Gateway, Nginx, etc.), enabling proxy-agnostic origin
 * validation driven by configuration rather than code.</p>
 *
 * <p>This contract applies to the socket peer address, not an application-level
 * {@code Origin} header or a forwarded client address. Implementations must not
 * trust request-controlled forwarding headers to make this decision.</p>
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
