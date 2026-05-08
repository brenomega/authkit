package io.github.brenomega.authkit.infrastructure.network.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Externalized configuration for the hybrid rate limiting filter (DT 3.2.21).
 *
 * <p>Binds properties from the {@code network.security.rate-limit} prefix to
 * type-safe fields, eliminating hardcoded defaults from the filter code.
 * Production values are defined in {@code application.yml}; test overrides
 * in {@code application-test.yml}.</p>
 *
 * <h3>Property Reference</h3>
 * <ul>
 *   <li>{@code network.security.rate-limit.local-capacity} — Layer 1 (Caffeine)
 *       per-IP bucket capacity per minute.</li>
 *   <li>{@code network.security.rate-limit.global-capacity} — Layer 2 (Redis)
 *       distributed per-IP bucket capacity per minute.</li>
 *   <li>{@code network.security.rate-limit.local-max-size} — Maximum number of
 *       IP buckets tracked in the local Caffeine cache.</li>
 * </ul>
 *
 * @see RateLimitingFilter
 */
@ConfigurationProperties(prefix = "network.security.rate-limit")
public class RateLimitingProperties {

    /**
     * Layer 1 (Caffeine) per-IP bucket capacity per minute.
     * Production default: 60 requests/min.
     */
    private int localCapacity = 60;

    /**
     * Layer 2 (Redis) distributed per-IP bucket capacity per minute.
     * Production default: 300 requests/min.
     */
    private int globalCapacity = 300;

    /**
     * Maximum number of IP buckets tracked in the local Caffeine cache.
     * Default: 100,000 entries.
     */
    private int localMaxSize = 100_000;

    public int getLocalCapacity() {
        return localCapacity;
    }

    public void setLocalCapacity(int localCapacity) {
        this.localCapacity = localCapacity;
    }

    public int getGlobalCapacity() {
        return globalCapacity;
    }

    public void setGlobalCapacity(int globalCapacity) {
        this.globalCapacity = globalCapacity;
    }

    public int getLocalMaxSize() {
        return localMaxSize;
    }

    public void setLocalMaxSize(int localMaxSize) {
        this.localMaxSize = localMaxSize;
    }
}
