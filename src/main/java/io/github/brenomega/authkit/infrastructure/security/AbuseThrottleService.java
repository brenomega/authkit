package io.github.brenomega.authkit.infrastructure.security;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.exception.RateLimitExceededException;
import io.github.brenomega.authkit.infrastructure.audit.AuditDigestService;
import io.github.brenomega.authkit.infrastructure.cache.Bucket4jProxyManagerFactory;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.lettuce.core.RedisClient;
import io.micrometer.core.instrument.MeterRegistry;

@Service
public class AbuseThrottleService {

    private static final Logger log = LoggerFactory.getLogger(AbuseThrottleService.class);
    private static final long LOG_THROTTLE_MS = Duration.ofMinutes(5).toMillis();

    private final Cache<String, Bucket> localBuckets;
    private final ProxyManager<byte[]> proxyManager;
    private final AuditDigestService auditDigestService;
    private final MeterRegistry meterRegistry;
    private final long capacityMultiplier;
    private final AtomicLong lastDegradedLogTimestamp = new AtomicLong(0);

    public AbuseThrottleService(Optional<RedisClient> redisClient,
                                AuditDigestService auditDigestService,
                                MeterRegistry meterRegistry,
                                AuthProperties authProperties) {
        this.auditDigestService = auditDigestService;
        this.meterRegistry = meterRegistry;
        this.capacityMultiplier = Math.max(1, authProperties.getAbuseControl().getCapacityMultiplier());
        this.localBuckets = Caffeine.newBuilder()
                .maximumSize(250_000)
                .expireAfterAccess(Duration.ofHours(25))
                .build();
        this.proxyManager = redisClient
                .map(client -> Bucket4jProxyManagerFactory.create(client, "AbuseThrottleService"))
                .orElse(null);

        if (this.proxyManager == null) {
            log.warn("AbuseThrottleService initialized without Redis. High-risk auth endpoints use strict degraded local limits.");
            meterRegistry.counter("security.abuse_control.degraded", "state", "startup_no_redis").increment();
        } else {
            log.info("AbuseThrottleService initialized with distributed Redis-backed endpoint/account throttles.");
        }
    }

    public void check(AbuseRateLimitPolicy policy, String dimension) {
        String normalized = normalizeDimension(dimension);
        String hashedDimension = auditDigestService.hmacHex(policy.key() + '|' + normalized);
        String key = policy.key() + ':' + hashedDimension;

        Bucket localBucket = localBuckets.get(key, ignored -> createBucket(scaledCapacity(policy.degradedLocalCapacity()), policy.window()));
        if (!localBucket.tryConsume(1)) {
            recordBlocked(policy, "local");
            throw new RateLimitExceededException();
        }

        if (proxyManager == null) {
            recordDegraded(policy, "redis_unavailable_startup");
            return;
        }

        try {
            Supplier<BucketConfiguration> config = () -> BucketConfiguration.builder()
                    .addLimit(Bandwidth.builder()
                            .capacity(scaledCapacity(policy.globalCapacity()))
                            .refillGreedy(scaledCapacity(policy.globalCapacity()), policy.window())
                            .build())
                    .build();
            Bucket globalBucket = proxyManager.builder().build(key.getBytes(StandardCharsets.UTF_8), config);
            if (!globalBucket.tryConsume(1)) {
                recordBlocked(policy, "redis");
                throw new RateLimitExceededException();
            }
        } catch (RateLimitExceededException ex) {
            throw ex;
        } catch (Exception ex) {
            recordDegraded(policy, "redis_runtime_failure");
            logDegraded("Redis unavailable for abuse throttle policy " + policy.key() + ". Strict local fallback remains active.");
        }
    }

    public void checkEmail(AbuseRateLimitPolicy policy, String email) {
        check(policy, "email:" + email);
    }

    public void checkUser(AbuseRateLimitPolicy policy, User user) {
        check(policy, "user:" + user.getId());
    }

    public void checkUserId(AbuseRateLimitPolicy policy, UUID userId) {
        check(policy, "user:" + userId);
    }

    public void checkTenant(AbuseRateLimitPolicy policy, UUID tenantId) {
        check(policy, "tenant:" + tenantId);
    }

    public void checkClient(AbuseRateLimitPolicy policy, String clientId) {
        check(policy, "client:" + clientId);
    }

    private Bucket createBucket(long capacity, Duration window) {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(capacity)
                        .refillGreedy(capacity, window)
                        .build())
                .build();
    }

    private long scaledCapacity(long capacity) {
        return Math.max(1, capacity * capacityMultiplier);
    }

    private void recordBlocked(AbuseRateLimitPolicy policy, String layer) {
        meterRegistry.counter("security.abuse_control.blocked", "policy", policy.key(), "layer", layer).increment();
    }

    private void recordDegraded(AbuseRateLimitPolicy policy, String reason) {
        if (policy.highRisk()) {
            meterRegistry.counter("security.abuse_control.degraded", "policy", policy.key(), "reason", reason).increment();
        }
    }

    private void logDegraded(String message) {
        long now = System.currentTimeMillis();
        long lastLog = lastDegradedLogTimestamp.get();
        if (now - lastLog > LOG_THROTTLE_MS && lastDegradedLogTimestamp.compareAndSet(lastLog, now)) {
            log.error(message);
        } else {
            log.debug("[Throttled] {}", message);
        }
    }

    private String normalizeDimension(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.trim().toLowerCase(java.util.Locale.ROOT);
    }
}
