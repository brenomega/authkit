package io.github.brenomega.authkit.infrastructure.security;

import java.time.Duration;
import java.util.UUID;
import java.util.function.Supplier;

import org.springframework.stereotype.Component;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;

/**
 * Caches whether an account has active TOTP enrollment for a bounded local interval.
 * Mutations must call {@link #evict(UUID)} so security decisions do not retain the
 * pre-change state until expiry; the cache is intentionally per process.
 */
@Component
public class MfaStatusCache {

    private final Cache<UUID, Boolean> cache;

    public MfaStatusCache(AuthProperties authProperties, MeterRegistry meterRegistry) {
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(authProperties.getMfa().getStatusCacheTtlSeconds()))
                .maximumSize(authProperties.getMfa().getStatusCacheMaxSize())
                .recordStats()
                .build();
        CaffeineCacheMetrics.monitor(meterRegistry, cache, "authkit.mfa_status_cache");
    }

    /** Returns cached state or atomically loads it for the local cache key. */
    public boolean isEnabled(UUID userId, Supplier<Boolean> loader) {
        return cache.get(userId, ignored -> loader.get());
    }

    public void evict(UUID userId) {
        cache.invalidate(userId);
    }
}
