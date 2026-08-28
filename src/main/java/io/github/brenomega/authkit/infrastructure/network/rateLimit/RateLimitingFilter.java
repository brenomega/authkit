package io.github.brenomega.authkit.infrastructure.network.rateLimit;

import io.github.brenomega.authkit.infrastructure.network.ip.NetworkIpResolver;
import io.github.brenomega.authkit.infrastructure.network.ip.IpMasker;
import io.github.brenomega.authkit.infrastructure.network.config.RateLimitingProperties;
import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

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
import io.github.brenomega.authkit.response.RequestContext;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Applies layered per-client-IP request budgets before endpoint-specific abuse controls.
 *
 * <p>Every process enforces a local one-minute bucket. When Redis is available, a
 * second one-minute bucket coordinates the configured global budget. Redis absence
 * or runtime failure deliberately degrades to local enforcement and emits failure
 * metrics; it does not fail requests closed. The resolved address is attached to
 * the request for downstream audit and privacy-reduced session metadata.</p>
 */
@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    private final NetworkIpResolver ipResolver;
    private final RateLimitingProperties properties;
    private final MeterRegistry meterRegistry;

    private final Cache<String, Bucket> localBuckets;

    private final ProxyManager<byte[]> proxyManager;

    private final Supplier<BucketConfiguration> globalBucketConfigSupplier;

    private final AtomicLong lastErrorLogTimestamp = new AtomicLong(0);
    private static final long LOG_THROTTLE_MS = Duration.ofMinutes(5).toMillis();

    public RateLimitingFilter(NetworkIpResolver ipResolver,
                              RateLimitingProperties properties,
                              Optional<RedisClient> redisClient,
                              MeterRegistry meterRegistry) {
        this.ipResolver = ipResolver;
        this.properties = properties;
        this.meterRegistry = meterRegistry;

        this.localBuckets = Caffeine.newBuilder()
                .maximumSize(properties.getLocalMaxSize())
                .expireAfterAccess(Duration.ofMinutes(2))
                .build();

        BucketConfiguration globalConfig = BucketConfiguration.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(properties.getGlobalCapacity())
                        .refillGreedy(properties.getGlobalCapacity(), Duration.ofMinutes(1))
                        .build())
                .build();
        this.globalBucketConfigSupplier = () -> globalConfig;

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

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String clientIp = ipResolver.resolveClientIp(request);

        request.setAttribute("X-Resolved-Client-IP", clientIp);

        Bucket localBucket = localBuckets.get(clientIp, key -> createNewLayer1Bucket());

        if (!localBucket.tryConsume(1)) {
            logRateLimitBlock(request, clientIp, "Layer 1 (Local)");
            sendRateLimitResponse(response);
            return;
        }

        if (proxyManager != null) {
            try {
                Bucket globalBucket = proxyManager.builder()
                        .build(clientIp.getBytes(StandardCharsets.UTF_8), globalBucketConfigSupplier);

                if (!globalBucket.tryConsume(1)) {
                    logRateLimitBlock(request, clientIp, "Layer 2 (Distributed)");
                    sendRateLimitResponse(response);
                    return;
                }
            } catch (Exception e) {

                meterRegistry.counter("security.infrastructure.failure", "component", "rate_limiter_redis").increment();
                logThrottledError(
                        "Redis proxy failure at runtime. Degrading to local limits. Error: " + e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }

    private Bucket createNewLayer1Bucket() {
        Bandwidth limit = Bandwidth.builder()
                .capacity(properties.getLocalCapacity())
                .refillGreedy(properties.getLocalCapacity(), Duration.ofMinutes(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

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

    private void sendRateLimitResponse(HttpServletResponse response) throws IOException {
        response.setStatus(429);
        response.setHeader("Retry-After", "60");
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        String jsonResponse = String.format(
            "{\"errors\":[\"Rate limit exceeded\"],"
                + "\"timestamp\":\"%s\",\"code\":\"rate_limit_exceeded\","
                + "\"requestId\":\"%s\"}",
            Instant.now(), RequestContext.currentRequestId()
        );
        response.getWriter().write(jsonResponse);
    }

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
