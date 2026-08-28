package io.github.brenomega.authkit.infrastructure.network.origin;

public interface TrustedOriginProvider {

    boolean isTrusted(String ip);
}
