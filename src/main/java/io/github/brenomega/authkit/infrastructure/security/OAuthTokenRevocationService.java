package io.github.brenomega.authkit.infrastructure.security;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.micrometer.core.instrument.MeterRegistry;

@Service
public class OAuthTokenRevocationService {

    private static final String KEY_PREFIX = "oauth:revoked-jti:";

    private final Optional<StringRedisTemplate> redisTemplate;
    private final Cache<String, Instant> localRevocations;
    private final MeterRegistry meterRegistry;

    public OAuthTokenRevocationService(Optional<StringRedisTemplate> redisTemplate,
                                       MeterRegistry meterRegistry) {
        this.redisTemplate = redisTemplate;
        this.meterRegistry = meterRegistry;
        this.localRevocations = Caffeine.newBuilder()
                .maximumSize(250_000)
                .expireAfterWrite(Duration.ofHours(2))
                .build();
    }

    public void revoke(String jti, Instant expiresAt) {
        if (jti == null || jti.isBlank() || expiresAt == null) {
            return;
        }
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        if (ttl.isNegative() || ttl.isZero()) {
            return;
        }
        localRevocations.put(jti, expiresAt);
        redisTemplate.ifPresent(template -> {
            try {
                template.opsForValue().set(KEY_PREFIX + jti, expiresAt.toString(), ttl);
            } catch (RuntimeException ex) {
                meterRegistry.counter("security.infrastructure.failure", "component", "oauth_token_revocation").increment();
            }
        });
    }

    public boolean isRevoked(String jti) {
        if (jti == null || jti.isBlank()) {
            return false;
        }
        Instant localExpiry = localRevocations.getIfPresent(jti);
        if (localExpiry != null) {
            if (localExpiry.isAfter(Instant.now())) {
                return true;
            }
            localRevocations.invalidate(jti);
        }
        return redisTemplate.map(template -> {
            try {
                return template.opsForValue().get(KEY_PREFIX + jti) != null;
            } catch (RuntimeException ex) {
                meterRegistry.counter("security.infrastructure.failure", "component", "oauth_token_revocation").increment();
                return false;
            }
        }).orElse(false);
    }
}
