package io.github.brenomega.authkit.infrastructure.security;

import java.time.Duration;
import java.util.Optional;
import java.util.function.Supplier;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.lettuce.core.RedisClient;
import io.github.brenomega.authkit.infrastructure.cache.Bucket4jProxyManagerFactory;
import io.github.brenomega.authkit.domain.user.util.EmailMasker;

@Service
public class AccountLockoutService {

    private static final Logger log = LoggerFactory.getLogger(AccountLockoutService.class);

    private final Cache<String, Bucket> localBuckets;
    private final ProxyManager<byte[]> proxyManager;
    private final Supplier<BucketConfiguration> bucketConfigSupplier;
    private final MeterRegistry meterRegistry;

    public AccountLockoutService(Optional<RedisClient> redisClient) {
        this(redisClient, new SimpleMeterRegistry());
    }

    @Autowired
    public AccountLockoutService(Optional<RedisClient> redisClient, MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;

        this.localBuckets = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterAccess(Duration.ofHours(24))
                .build();

        BucketConfiguration config = BucketConfiguration.builder()
                .addLimit(Bandwidth.builder().capacity(5).refillIntervally(5, Duration.ofMinutes(15)).build())
                .addLimit(Bandwidth.builder().capacity(10).refillIntervally(10, Duration.ofHours(1)).build())
                .addLimit(Bandwidth.builder().capacity(15).refillIntervally(15, Duration.ofHours(24)).build())
                .build();
        this.bucketConfigSupplier = () -> config;

        this.proxyManager = redisClient
                .map(client -> Bucket4jProxyManagerFactory.create(client, "AccountLockoutService"))
                .orElse(null);

        if (this.proxyManager != null) {
            log.info("AccountLockoutService initialized with distributed Layer 2 " +
                "(Redis) and progressive multi-bandwidth policy (DT 3.2.23).");
        } else {
            log.warn("AccountLockoutService initialized with Layer 1 only. Redis " +
                "client unavailable; lockout degrades to per-node local " +
                "enforcement.");
            meterRegistry.counter("security.lockout.degraded", "reason", "startup_no_redis").increment();
        }
    }

    public void recordFailedAttempt(String email) {
        try {
            Bucket localBucket = localBuckets.get(email, key -> createNewLayer1Bucket());
            localBucket.tryConsume(1);

            if (proxyManager != null) {
                Bucket globalBucket = proxyManager.builder()
                        .build(email.getBytes(StandardCharsets.UTF_8), bucketConfigSupplier);
                globalBucket.tryConsume(1);
            }
            log.debug("Failed attempt recorded for account: {}", EmailMasker.mask(email));
        } catch (Exception e) {
            meterRegistry.counter("security.infrastructure.failure", "component", "lockout_redis").increment();
            meterRegistry.counter("security.lockout.degraded", "reason", "redis_runtime_failure").increment();
            log.error("Redis unavailable while recording lockout state. Per-node local lockout remains active.");
        }
    }

    public boolean isLocked(String email) {
        try {
            if (proxyManager != null) {
                Bucket globalBucket = proxyManager.builder()
                        .build(email.getBytes(StandardCharsets.UTF_8), bucketConfigSupplier);
                if (globalBucket.getAvailableTokens() == 0) {
                    return true;
                }
            } else {
                Bucket localBucket = localBuckets.getIfPresent(email);
                if (localBucket != null && localBucket.getAvailableTokens() == 0) {
                    return true;
                }
            }
        } catch (Exception e) {
            meterRegistry.counter("security.infrastructure.failure", "component", "lockout_redis").increment();
            meterRegistry.counter("security.lockout.degraded", "reason", "redis_runtime_failure").increment();
            log.error("Redis unavailable for lockout check. Falling back to per-node local lockout.");
            Bucket localBucket = localBuckets.getIfPresent(email);
            return localBucket != null && localBucket.getAvailableTokens() == 0;
        }

        return false;
    }

    public void clearLockout(String email) {
        localBuckets.invalidate(email);

        if (proxyManager != null) {
            try {
                proxyManager.removeProxy(email.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                meterRegistry.counter("security.infrastructure.failure", "component", "lockout_redis").increment();
                meterRegistry.counter("security.lockout.degraded", "reason", "redis_runtime_failure").increment();
                log.error("Redis unavailable for lockout clearing. Local cache cleared; " +
                    "distributed lockout state may persist.");
            }
        }

        log.info("Lockout cleared for account after a successful trusted recovery or authentication ceremony.");
    }

    private Bucket createNewLayer1Bucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder().capacity(5).refillIntervally(5, Duration.ofMinutes(15)).build())
                .addLimit(Bandwidth.builder().capacity(10).refillIntervally(10, Duration.ofHours(1)).build())
                .addLimit(Bandwidth.builder().capacity(15).refillIntervally(15, Duration.ofHours(24)).build())
                .build();
    }
}
