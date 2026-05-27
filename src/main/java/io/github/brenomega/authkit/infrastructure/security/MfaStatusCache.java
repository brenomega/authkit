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
 * Short-lived MFA status cache used to keep refresh/login hot paths away from
 * repetitive existence checks on the TOTP table.
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

    public boolean isEnabled(UUID userId, Supplier<Boolean> loader) {
        return cache.get(userId, ignored -> loader.get());
    }

    public void evict(UUID userId) {
        cache.invalidate(userId);
    }
}
