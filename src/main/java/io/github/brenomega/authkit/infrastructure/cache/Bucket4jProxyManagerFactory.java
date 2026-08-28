package io.github.brenomega.authkit.infrastructure.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;

public final class Bucket4jProxyManagerFactory {

    private static final Logger log = LoggerFactory.getLogger(Bucket4jProxyManagerFactory.class);

    private Bucket4jProxyManagerFactory() {
    }

    public static ProxyManager<byte[]> create(RedisClient client, String callerName) {
        try {
            return LettuceBasedProxyManager.builderFor(client).build();
        } catch (Exception e) {
            log.error("Failed to build LettuceBasedProxyManager for {}. " +
                      "Distributed rate limiting disabled (DT 3.1.18 fail-open). Error: {}",
                      callerName, e.getMessage());
            return null;
        }
    }
}
