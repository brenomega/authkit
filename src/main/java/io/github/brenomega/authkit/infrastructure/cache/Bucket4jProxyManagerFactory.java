package io.github.brenomega.authkit.infrastructure.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;

/**
 * Shared factory for creating Bucket4j {@link ProxyManager} instances from a
 * Lettuce {@link RedisClient} (DT 3.2.21).
 *
 * <p>Implements the fail-open pattern (DT 3.1.18): if construction fails,
 * returns {@code null} so callers can gracefully degrade to local-only
 * operation.</p>
 */
public final class Bucket4jProxyManagerFactory {

    private static final Logger log = LoggerFactory.getLogger(Bucket4jProxyManagerFactory.class);

    private Bucket4jProxyManagerFactory() {
    }

    /**
     * Builds a {@link ProxyManager} from the given Redis client.
     *
     * @param client     the Lettuce Redis client
     * @param callerName a human-readable name for log attribution
     * @return the constructed proxy manager, or {@code null} on failure
     */
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
