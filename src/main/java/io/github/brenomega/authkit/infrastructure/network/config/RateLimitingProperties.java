package io.github.brenomega.authkit.infrastructure.network.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "network.security.rate-limit")
public class RateLimitingProperties {

    private int localCapacity = 60;

    private int globalCapacity = 300;

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
