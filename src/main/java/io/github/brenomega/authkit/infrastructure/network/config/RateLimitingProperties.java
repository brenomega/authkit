package io.github.brenomega.authkit.infrastructure.network.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Configures the per-IP local and distributed one-minute request budgets. */
@ConfigurationProperties(prefix = "network.security.rate-limit")
public class RateLimitingProperties {

    /** Requests per minute allowed by each process before distributed enforcement. */
    private int localCapacity = 60;

    /** Requests per minute allowed across processes when Redis is available. */
    private int globalCapacity = 300;

    /** Maximum number of client-IP buckets retained by one process. */
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
