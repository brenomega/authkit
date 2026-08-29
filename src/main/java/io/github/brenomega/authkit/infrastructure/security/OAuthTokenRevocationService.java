package io.github.brenomega.authkit.infrastructure.security;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.micrometer.core.instrument.MeterRegistry;
import io.github.brenomega.authkit.exception.TokenRevocationUnavailableException;

/**
 * Tracks revoked OAuth access-token JTIs until their natural expiry.
 *
 * <p>The configured Redis or JDBC store is authoritative and the local cache is
 * only a positive-result accelerator. Read or write degradation is metered and
 * fails closed so endpoints that promise live token state never revive a JTI.</p>
 */
@Service
public class OAuthTokenRevocationService {

    private static final String KEY_PREFIX = "oauth:revoked-jti:";

    private final Optional<StringRedisTemplate> redisTemplate;
    private final Optional<JdbcOAuthTokenRevocationStore> jdbcStore;
    private final Cache<String, Instant> localRevocations;
    private final MeterRegistry meterRegistry;
    private final boolean redisRevocationEnabled;

    public OAuthTokenRevocationService(Optional<StringRedisTemplate> redisTemplate,
                                       Optional<JdbcOAuthTokenRevocationStore> jdbcStore,
                                       AuthProperties authProperties,
                                       MeterRegistry meterRegistry) {
        this.redisTemplate = redisTemplate;
        this.jdbcStore = jdbcStore;
        this.meterRegistry = meterRegistry;
        this.redisRevocationEnabled = "redis".equals(authProperties.getTokenStorage().getBackend());
        this.localRevocations = Caffeine.newBuilder()
                .maximumSize(250_000)
                .expireAfterWrite(Duration.ofHours(2))
                .build();
    }

    @SuppressWarnings("null")
    public void revoke(String jti, Instant expiresAt) {
        if (jti == null || jti.isBlank() || expiresAt == null) {
            return;
        }
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        if (ttl.isNegative() || ttl.isZero()) {
            return;
        }
        if (redisRevocationEnabled) {
            try {
                StringRedisTemplate template = redisTemplate
                        .orElseThrow(TokenRevocationUnavailableException::new);
                template.opsForValue().set(KEY_PREFIX + jti, expiresAt.toString(), ttl);
            } catch (RuntimeException ex) {
                meterRegistry.counter(
                    "security.infrastructure.failure",
                    "component",
                    "oauth_token_revocation").increment();
                if (ex instanceof TokenRevocationUnavailableException unavailable) {
                    throw unavailable;
                }
                throw new TokenRevocationUnavailableException(ex);
            }
        } else {
            try {
                jdbcStore.orElseThrow(TokenRevocationUnavailableException::new).revoke(jti, expiresAt);
            } catch (RuntimeException ex) {
                meterRegistry.counter(
                    "security.infrastructure.failure",
                    "component",
                    "oauth_token_revocation_jdbc").increment();
                if (ex instanceof TokenRevocationUnavailableException unavailable) {
                    throw unavailable;
                }
                throw new TokenRevocationUnavailableException(ex);
            }
        }
        localRevocations.put(jti, expiresAt);
    }

    /** Returns whether the JTI is durably revoked and fails closed on lookup degradation. */
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
        if (!redisRevocationEnabled) {
            try {
                return jdbcStore.orElseThrow(TokenRevocationUnavailableException::new).isRevoked(jti);
            } catch (RuntimeException ex) {
                meterRegistry.counter(
                    "security.infrastructure.failure",
                    "component",
                    "oauth_token_revocation_jdbc").increment();
                if (ex instanceof TokenRevocationUnavailableException unavailable) {
                    throw unavailable;
                }
                throw new TokenRevocationUnavailableException(ex);
            }
        }
        try {
            StringRedisTemplate template = redisTemplate
                    .orElseThrow(TokenRevocationUnavailableException::new);
            return template.opsForValue().get(KEY_PREFIX + jti) != null;
        } catch (RuntimeException ex) {
            meterRegistry.counter(
                "security.infrastructure.failure",
                "component",
                "oauth_token_revocation").increment();
            if (ex instanceof TokenRevocationUnavailableException unavailable) {
                throw unavailable;
            }
            throw new TokenRevocationUnavailableException(ex);
        }
    }
}
