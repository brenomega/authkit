package io.github.brenomega.authkit.infrastructure.network.origin;

/**
 * Decides whether a direct network peer belongs to the deployment trust perimeter.
 * Implementations must interpret the supplied value as an address, never as a
 * forwarded-header identity.
 */
public interface TrustedOriginProvider {

    /** Returns whether the peer is allowed to reach origin-protected processing. */
    boolean isTrusted(String ip);
}
