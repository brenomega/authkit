package io.github.brenomega.authkit.infrastructure.network.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configures the local micro-burst and global per-address request budgets.
 *
 * <p>Both capacities are requests per minute. The local cache size bounds memory,
 * while Redis supplies the cross-instance global budget when available.</p>
 *
 * @see io.github.brenomega.authkit.infrastructure.network.rateLimit.RateLimitingFilter
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
