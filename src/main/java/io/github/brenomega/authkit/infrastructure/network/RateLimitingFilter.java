package io.github.brenomega.authkit.infrastructure.network;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.lang.NonNull;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Hybrid rate limiting filter enforcing volumetric request bounds (DT 3.2.21).
 *
 * <p>Implements the <strong>Defense in Depth</strong> strategy (DT 3.2.16) by applying
 * application-level rate limits that are strictly tighter than the edge proxy limits.
 * While the edge (e.g., Cloudflare, AWS WAF) blocks volumetric DDoS at the infrastructure
 * layer, this filter handles application-specific abuse (e.g., credential stuffing,
 * resource enumeration) that may bypass the edge.</p>
 *
 * <p>Operates in two layers to eliminate race conditions in distributed environments:</p>
 * <ul>
 *   <li><strong>Layer 1 — Local (Bucket4j + Caffeine):</strong> Strict, sub-millisecond
 *       latency enforcement to block micro-bursts on the same instance. Capacity is
 *       configured via {@link RateLimitingProperties#getLocalCapacity()}.</li>
 *   <li><strong>Layer 2 — Distributed (Bucket4j + Redis):</strong> Global state
 *       synchronization across horizontally-scaled instances. Capacity is configured
 *       via {@link RateLimitingProperties#getGlobalCapacity()}.</li>
 * </ul>
 *
 * <h3>Heap Optimization</h3>
 * <p>Both {@link BucketConfiguration} instances (local and global) are pre-computed at
 * construction time and reused across all requests. The {@code doFilterInternal} hot path
 * performs zero configuration-object allocations.</p>
 *
 * <h3>Fail-Open (DT 3.1.18)</h3>
 * <p>If Redis is unreachable (either at startup or at runtime), the filter degrades
 * gracefully to Layer 1 only, maintaining availability at the cost of cross-instance
 * consistency.</p>
 *
 * <h3>Log Throttling (DT 3.4.1)</h3>
 * <p>Redis failures are logged at most once every 5 minutes to prevent production
 * log flooding during sustained outages.</p>
 *
 * @see RateLimitingProperties
 * @see NetworkIPResolver
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    private final NetworkIPResolver ipResolver;
    private final RateLimitingProperties properties;

    /** DT 3.2.21 — Layer 1 local Caffeine cache bounding micro-burst logic unconditionally. */
    private final Cache<String, Bucket> localBuckets;

    /** DT 3.2.21 — Layer 2 global Redis proxy. Null when Redis is unavailable (fail-open). */
    private final ProxyManager<byte[]> proxyManager;

    /** Pre-computed Layer 2 bucket configuration (heap optimization). */
    private final Supplier<BucketConfiguration> globalBucketConfigSupplier;

    /** DT 3.4.1 — Log throttling timestamp for Redis failure messages. */
    private final AtomicLong lastErrorLogTimestamp = new AtomicLong(0);
    private static final long LOG_THROTTLE_MS = Duration.ofMinutes(5).toMillis();

    /**
     * Constructs the filter with externalized configuration and optional Redis client.
     *
     * <p>If a {@link RedisClient} bean is available (production), the distributed
     * Layer 2 {@link ProxyManager} is built eagerly. If absent (test profile or
     * Redis-less environments), Layer 2 is disabled and the filter operates with
     * Layer 1 only (DT 3.1.18 fail-open).</p>
     *
     * @param ipResolver  resolves the real client IP from headers (DT 3.2.17, DT 3.2.20)
     * @param properties  externalized rate limiting configuration (DT 3.2.21)
     * @param redisClient optional Lettuce client for distributed rate limiting
     */
    public RateLimitingFilter(NetworkIPResolver ipResolver,
                              RateLimitingProperties properties,
                              Optional<RedisClient> redisClient) {
        this.ipResolver = ipResolver;
        this.properties = properties;

        // Layer 1 — Caffeine local cache
        this.localBuckets = Caffeine.newBuilder()
                .maximumSize(properties.getLocalMaxSize())
                .expireAfterAccess(Duration.ofHours(1))
                .build();

        // Pre-compute global BucketConfiguration (heap optimization — zero allocations on hot path)
        BucketConfiguration globalConfig = BucketConfiguration.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(properties.getGlobalCapacity())
                        .refillGreedy(properties.getGlobalCapacity(), Duration.ofMinutes(1))
                        .build())
                .build();
        this.globalBucketConfigSupplier = () -> globalConfig;

        // Layer 2 — Redis ProxyManager (eagerly built if client is available)
        this.proxyManager = redisClient
                .map(this::buildProxyManager)
                .orElse(null);

        if (this.proxyManager != null) {
            log.info("RateLimitingFilter initialized with distributed Layer 2 (Redis). " +
                     "Local capacity: {}/min, Global capacity: {}/min (DT 3.2.16, DT 3.2.21)",
                     properties.getLocalCapacity(), properties.getGlobalCapacity());
        } else {
            log.warn("RateLimitingFilter initialized with Layer 1 only (Caffeine). " +
                     "Redis client unavailable — distributed rate limiting disabled (DT 3.1.18 fail-open). " +
                     "Local capacity: {}/min", properties.getLocalCapacity());
        }
    }

    /**
     * Applies the two-layer rate limiting logic to every incoming request (DT 3.2.21).
     *
     * <p>When a request is blocked (HTTP 429), the resolved client IP and edge
     * proxy headers (if present) are logged for forensic analysis of
     * edge-bypass attempts (DT 3.2.16).</p>
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // Resolve priority IP natively matching the proxy layout (DT 3.2.17, DT 3.2.20)
        String clientIp = ipResolver.resolveClientIp(request);

        // DT 3.2.21 — Acquire local burst bucket (Layer 1)
        Bucket localBucket = localBuckets.get(clientIp, key -> createNewLayer1Bucket());

        if (!localBucket.tryConsume(1)) {
            logRateLimitBlock(request, clientIp, "Layer 1 (Local)");
            response.setStatus(429);
            response.getWriter().write("Too Many Requests");
            return;
        }

        // DT 3.2.21 — Acquire global Redis cluster bucket (Layer 2)
        if (proxyManager != null) {
            try {
                Bucket globalBucket = proxyManager.builder()
                        .build(clientIp.getBytes(), globalBucketConfigSupplier);

                if (!globalBucket.tryConsume(1)) {
                    logRateLimitBlock(request, clientIp, "Layer 2 (Distributed)");
                    response.setStatus(429);
                    response.getWriter().write("Too Many Requests");
                    return;
                }
            } catch (Exception e) {
                // Fail-open: DT 3.2.21 & DT 3.1.18 — Redis unavailable at runtime, degrade to Layer 1
                logThrottledError("Redis proxy failure at runtime. Degrading to local limits. Error: " + e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Creates a new Layer 1 local bucket with externalized capacity (DT 3.2.21).
     *
     * @return a new Bucket configured with the local capacity from properties
     */
    private Bucket createNewLayer1Bucket() {
        Bandwidth limit = Bandwidth.builder()
                .capacity(properties.getLocalCapacity())
                .refillGreedy(properties.getLocalCapacity(), Duration.ofMinutes(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    /**
     * Builds the distributed {@link ProxyManager} from the injected {@link RedisClient}.
     *
     * <p>If construction fails (e.g., misconfigured client), returns {@code null}
     * to trigger fail-open behavior (DT 3.1.18).</p>
     *
     * @param client the Lettuce Redis client
     * @return the constructed ProxyManager, or {@code null} on failure
     */
    private ProxyManager<byte[]> buildProxyManager(RedisClient client) {
        try {
            return LettuceBasedProxyManager.builderFor(client).build();
        } catch (Exception e) {
            log.error("Failed to build LettuceBasedProxyManager. " +
                      "Distributed rate limiting disabled (DT 3.1.18 fail-open). Error: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Logs rate limit enforcement with forensic context for edge-bypass analysis (DT 3.2.16).
     *
     * <p>Includes the resolved client IP and the raw {@code CF-Connecting-IP} header
     * to help identify requests that may have bypassed Cloudflare.</p>
     *
     * @param request  the blocked HTTP request
     * @param clientIp the resolved client IP
     * @param layer    which rate limiting layer triggered the block
     */
    private void logRateLimitBlock(HttpServletRequest request, String clientIp, String layer) {
        String cfIp = request.getHeader("CF-Connecting-IP");
        String method = request.getMethod();
        String uri = request.getRequestURI();

        if (cfIp != null && !cfIp.isBlank()) {
            log.warn("Rate limit triggered [{}]: {} {} | Resolved IP: {} | CF-Connecting-IP: {} (DT 3.2.16)",
                     layer, method, uri, clientIp, cfIp);
        } else {
            log.warn("Rate limit triggered [{}]: {} {} | Direct IP: {} | No CF-Connecting-IP header — " +
                     "possible edge bypass (DT 3.2.16)", layer, method, uri, clientIp);
        }
    }

    /**
     * Emits an ERROR log only if the throttle window has passed, otherwise demotes to DEBUG (DT 3.4.1).
     *
     * @param message the error message to log
     */
    private void logThrottledError(String message) {
        long now = System.currentTimeMillis();
        long lastLog = lastErrorLogTimestamp.get();

        if (now - lastLog > LOG_THROTTLE_MS) {
            if (lastErrorLogTimestamp.compareAndSet(lastLog, now)) {
                log.error(message);
                return;
            }
        }
        log.debug("[Throttled] {}", message);
    }
}
