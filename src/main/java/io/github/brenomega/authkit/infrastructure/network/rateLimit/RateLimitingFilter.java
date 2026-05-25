package io.github.brenomega.authkit.infrastructure.network.rateLimit;

import io.github.brenomega.authkit.infrastructure.network.ip.NetworkIpResolver;
import io.github.brenomega.authkit.infrastructure.network.ip.IpMasker;
import io.github.brenomega.authkit.infrastructure.network.config.RateLimitingProperties;
import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.lang.NonNull;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.lettuce.core.RedisClient;
import io.micrometer.core.instrument.MeterRegistry;
import io.github.brenomega.authkit.infrastructure.cache.Bucket4jProxyManagerFactory;

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
 * @see NetworkIpResolver
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    private final NetworkIpResolver ipResolver;
    private final RateLimitingProperties properties;
    private final MeterRegistry meterRegistry;

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
     * @param meterRegistry the meter registry for tracking dropped requests
     */
    public RateLimitingFilter(NetworkIpResolver ipResolver,
                              RateLimitingProperties properties,
                              Optional<RedisClient> redisClient,
                              MeterRegistry meterRegistry) {
        this.ipResolver = ipResolver;
        this.properties = properties;
        this.meterRegistry = meterRegistry;

        // Layer 1 — Caffeine local cache
        this.localBuckets = Caffeine.newBuilder()
                .maximumSize(properties.getLocalMaxSize())
                .expireAfterAccess(Duration.ofMinutes(2))
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
                .map(client -> Bucket4jProxyManagerFactory.create(client, "RateLimitingFilter"))
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

        // Expose resolved IP to downstream application logic to eliminate redundant resolution
        request.setAttribute("X-Resolved-Client-IP", clientIp);

        // DT 3.2.21 — Acquire local burst bucket (Layer 1)
        Bucket localBucket = localBuckets.get(clientIp, key -> createNewLayer1Bucket());

        if (!localBucket.tryConsume(1)) {
            logRateLimitBlock(request, clientIp, "Layer 1 (Local)");
            sendRateLimitResponse(response);
            return;
        }

        // DT 3.2.21 — Acquire global Redis cluster bucket (Layer 2)
        if (proxyManager != null) {
            try {
                Bucket globalBucket = proxyManager.builder()
                        .build(clientIp.getBytes(java.nio.charset.StandardCharsets.UTF_8), globalBucketConfigSupplier);

                if (!globalBucket.tryConsume(1)) {
                    logRateLimitBlock(request, clientIp, "Layer 2 (Distributed)");
                    sendRateLimitResponse(response);
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
        String traceId = request.getHeader("CF-RAY");
        String method = request.getMethod();
        String uri = request.getRequestURI();

        meterRegistry.counter("rate.limit.dropped", "layer", layer).increment();

        if (traceId != null) {
            MDC.put("traceId", traceId);
        }

        try {
            if (cfIp != null && !cfIp.isBlank()) {
                log.warn("Rate limit triggered [{}]: {} {} | Resolved IP: {} | CF-Connecting-IP: {} (DT 3.2.16)",
                         layer, method, uri, IpMasker.mask(clientIp), IpMasker.mask(cfIp));
            } else {
                log.warn("Rate limit triggered [{}]: {} {} | Direct IP: {} | No CF-Connecting-IP header — " +
                         "possible edge bypass (DT 3.2.16)", layer, method, uri, IpMasker.mask(clientIp));
            }
        } finally {
            MDC.remove("traceId");
        }
    }

    /**
     * Sends a structured JSON response for rate limit violations.
     *
     * @param response the HTTP servlet response
     * @throws IOException if writing to the response fails
     */
    private void sendRateLimitResponse(HttpServletResponse response) throws IOException {
        response.setStatus(429);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        String jsonResponse = String.format(
            "{\"timestamp\":\"%s\",\"status\":429,\"error\":\"Too Many Requests\",\"message\":\"Rate limit exceeded\"}",
            java.time.Instant.now().toString()
        );
        response.getWriter().write(jsonResponse);
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
