package io.github.brenomega.authkit.infrastructure.security;

import java.time.Duration;
import java.util.Optional;
import java.util.function.Supplier;

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

/**
 * Maintains progressive account lockout across local and distributed budgets.
 *
 * <p>Redis-backed Bucket4j state is the cross-instance authority; a Caffeine layer
 * bounds local micro-bursts and remains the fallback when Redis is unavailable.
 * The three concurrent thresholds enforce 5 attempts per 15 minutes, 10 per hour,
 * and 15 per 24 hours. Degraded enforcement is therefore per-instance.</p>
 *
 * <p>Lockout is cleared only after a complete successful authentication ceremony
 * or successful password recovery, never after password verification alone.</p>
 *
 * @see io.github.brenomega.authkit.exception.AccountLockedException
 */
@Service
public class AccountLockoutService {

    private static final Logger log = LoggerFactory.getLogger(AccountLockoutService.class);

    private final Cache<String, Bucket> localBuckets;
    private final ProxyManager<byte[]> proxyManager;
    private final Supplier<BucketConfiguration> bucketConfigSupplier;
    private final MeterRegistry meterRegistry;

    /**
     * Constructs the hybrid lockout service.
     *
     * @param redisClient the optional Redis client for global state persistence
     */
    public AccountLockoutService(Optional<RedisClient> redisClient) {
        this(redisClient, new SimpleMeterRegistry());
    }

    @Autowired
    public AccountLockoutService(Optional<RedisClient> redisClient, MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        // Layer 1 — Caffeine local cache
        this.localBuckets = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterAccess(Duration.ofHours(24)) // Align with max lockout window
                .build();

        // Pre-compute BucketConfiguration (heap optimization)
        BucketConfiguration config = BucketConfiguration.builder()
                .addLimit(Bandwidth.builder().capacity(5).refillIntervally(5, Duration.ofMinutes(15)).build())
                .addLimit(Bandwidth.builder().capacity(10).refillIntervally(10, Duration.ofHours(1)).build())
                .addLimit(Bandwidth.builder().capacity(15).refillIntervally(15, Duration.ofHours(24)).build())
                .build();
        this.bucketConfigSupplier = () -> config;

        // Layer 2 — Redis ProxyManager
        this.proxyManager = redisClient
                .map(client -> Bucket4jProxyManagerFactory.create(client, "AccountLockoutService"))
                .orElse(null);

        if (this.proxyManager != null) {
            log.info("AccountLockoutService initialized with distributed Layer 2 (Redis) and progressive multi-bandwidth policy (DT 3.2.23).");
        } else {
            log.warn("AccountLockoutService initialized with Layer 1 only. Redis client unavailable; lockout degrades to per-node local enforcement.");
            meterRegistry.counter("security.lockout.degraded", "reason", "startup_no_redis").increment();
        }
    }

    /**
     * Records a failed authentication attempt for the given email (DT 3.2.23).
     *
     * <p>Consumes 1 penalty token from the progressive bucket. If the bucket
     * is already empty, this operation simply fails to consume, maintaining the lock.</p>
     *
     * @param email the email associated with the failed attempt
     */
    public void recordFailedAttempt(String email) {
        try {
            Bucket localBucket = localBuckets.get(email, key -> createNewLayer1Bucket());
            localBucket.tryConsume(1);

            if (proxyManager != null) {
                Bucket globalBucket = proxyManager.builder()
                        .build(email.getBytes(java.nio.charset.StandardCharsets.UTF_8), bucketConfigSupplier);
                globalBucket.tryConsume(1);
            }
            log.debug("Failed attempt recorded for account: {}", EmailMasker.mask(email));
        } catch (Exception e) {
            meterRegistry.counter("security.infrastructure.failure", "component", "lockout_redis").increment();
            meterRegistry.counter("security.lockout.degraded", "reason", "redis_runtime_failure").increment();
            log.error("Redis unavailable while recording lockout state. Per-node local lockout remains active.");
        }
    }

    /**
     * Checks whether the account associated with the given email is currently locked (DT 3.2.23).
     *
     * <p>Evaluates if the bucket has 0 available tokens across any of its progressive limits.
     * This method does not consume tokens.</p>
     *
     * @param email the email to check
     * @return {@code true} if the account has exhausted any progressive threshold
     */
    public boolean isLocked(String email) {
        try {
            if (proxyManager != null) {
                Bucket globalBucket = proxyManager.builder()
                        .build(email.getBytes(java.nio.charset.StandardCharsets.UTF_8), bucketConfigSupplier);
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

    /**
     * Clears the lockout counter for the given email (DT 3.2.23).
     *
     * <p>This is the <strong>only</strong> sanctioned unlock path and must be
     * called exclusively after a successful password reset via email.</p>
     *
     * <p>Completely removes the bucket state from Redis and invalidates local caches.</p>
     *
     * @param email the email whose lockout should be cleared
     */
    public void clearLockout(String email) {
        localBuckets.invalidate(email);

        if (proxyManager != null) {
            try {
                proxyManager.removeProxy(email.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            } catch (Exception e) {
                meterRegistry.counter("security.infrastructure.failure", "component", "lockout_redis").increment();
                meterRegistry.counter("security.lockout.degraded", "reason", "redis_runtime_failure").increment();
                log.error("Redis unavailable for lockout clearing. Local cache cleared; distributed lockout state may persist.");
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
