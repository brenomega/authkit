package io.github.brenomega.authkit.infrastructure.cache;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Hybrid service for managing progressive account lockout state (DT 3.2.23).
 *
 * <p>Uses a two-layer architecture for horizontal scalability:</p>
 * <ul>
 *   <li><strong>Layer 1 — Redis (Source of Truth):</strong> Tracks failed attempt
 *       counts globally via {@code INCR} with a 15-minute TTL. This ensures
 *       consistency across horizontally-scaled instances.</li>
 *   <li><strong>Layer 2 — Caffeine (L1 Read Cache):</strong> Caches positive
 *       lockout results locally for 1 minute to reduce Redis round-trip time
 *       on frequently-checked accounts.</li>
 * </ul>
 *
 * <p><strong>Fail-Open (DT 3.1.18):</strong> If Redis is unreachable, all
 * operations degrade gracefully to the local Caffeine cache, maintaining
 * per-instance lockout enforcement without cross-instance consistency.</p>
 *
 * <h3>Integration Points</h3>
 * <ul>
 *   <li><strong>{@code AuthService}</strong> — records failures on bad credentials
 *       and checks lockout before processing login (DT 3.2.15 stealth response).</li>
 *   <li><strong>{@code ProfileService}</strong> — checks lockout before allowing
 *       password change or session revocation on management endpoints.</li>
 *   <li><strong>{@code PasswordRecoveryService}</strong> — clears lockout after
 *       successful email-based password reset (the ONLY unlock path).</li>
 * </ul>
 *
 * @see io.github.brenomega.authkit.exception.AccountLockedException
 */
@Service
public class AccountLockoutService {

    private static final Logger log = LoggerFactory.getLogger(AccountLockoutService.class);

    /** Redis key prefix for lockout attempt counters. */
    private static final String KEY_PREFIX = "lockout:attempts:";

    /** Number of failed attempts before the account is locked. */
    private static final int MAX_ATTEMPTS = 5;

    /** Duration of the lockout window (DT 3.2.23: 15 minutes initial). */
    private static final Duration LOCKOUT_WINDOW = Duration.ofMinutes(15);

    private final StringRedisTemplate redisTemplate;

    /**
     * L1 Caffeine cache for positive lockout status (reduces Redis RTT).
     * Entries expire after 1 minute to balance freshness vs. performance.
     */
    private final Cache<String, Boolean> lockoutStatusCache;

    /**
     * Fallback Caffeine cache for tracking attempt counts when Redis is unavailable.
     * Mirrors the Redis TTL of 15 minutes.
     */
    private final Cache<String, Integer> fallbackAttemptsCache;

    /**
     * Constructs the hybrid lockout service.
     *
     * @param redisTemplate the Redis template for global state persistence
     */
    public AccountLockoutService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.lockoutStatusCache = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(Duration.ofMinutes(1))
                .build();
        this.fallbackAttemptsCache = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(LOCKOUT_WINDOW)
                .build();
    }

    /**
     * Records a failed authentication attempt for the given email (DT 3.2.23).
     *
     * <p>Increments the counter in Redis with a 15-minute TTL. If Redis is
     * unavailable, increments the local fallback cache instead.</p>
     *
     * @param email the email associated with the failed attempt
     */
    public void recordFailedAttempt(String email) {
        String key = KEY_PREFIX + email;
        try {
            Long count = redisTemplate.opsForValue().increment(key);
            redisTemplate.expire(key, LOCKOUT_WINDOW.toMinutes(), TimeUnit.MINUTES);
            log.debug("Failed attempt #{} recorded in Redis for account.", count);

            // Proactively cache lockout status if threshold reached
            if (count != null && count >= MAX_ATTEMPTS) {
                lockoutStatusCache.put(email, Boolean.TRUE);
            }
        } catch (Exception e) {
            // Fail-open: fall back to local cache
            log.debug("Redis unavailable for lockout recording. Falling back to local cache. Error: {}", e.getMessage());
            Integer attempts = fallbackAttemptsCache.getIfPresent(email);
            int newCount = (attempts == null) ? 1 : attempts + 1;
            fallbackAttemptsCache.put(email, newCount);
            log.debug("Failed attempt #{} recorded in local fallback cache.", newCount);

            if (newCount >= MAX_ATTEMPTS) {
                lockoutStatusCache.put(email, Boolean.TRUE);
            }
        }
    }

    /**
     * Checks whether the account associated with the given email is currently locked (DT 3.2.23).
     *
     * <p>Check order:</p>
     * <ol>
     *   <li>L1 Caffeine cache (sub-microsecond latency).</li>
     *   <li>Redis global counter (source of truth).</li>
     *   <li>Local fallback cache (if Redis is unavailable).</li>
     * </ol>
     *
     * @param email the email to check
     * @return {@code true} if the account has reached or exceeded the lockout threshold
     */
    public boolean isLocked(String email) {
        // L1: Check local lockout status cache first
        Boolean cachedStatus = lockoutStatusCache.getIfPresent(email);
        if (cachedStatus != null && cachedStatus) {
            return true;
        }

        // L2: Query Redis for the authoritative count
        try {
            String key = KEY_PREFIX + email;
            String countStr = redisTemplate.opsForValue().get(key);
            if (countStr != null) {
                int count = Integer.parseInt(countStr);
                if (count >= MAX_ATTEMPTS) {
                    // Cache positive result in L1
                    lockoutStatusCache.put(email, Boolean.TRUE);
                    return true;
                }
            }
        } catch (Exception e) {
            // Fail-open: fall back to local cache
            log.debug("Redis unavailable for lockout check. Falling back to local cache. Error: {}", e.getMessage());
            Integer localAttempts = fallbackAttemptsCache.getIfPresent(email);
            return localAttempts != null && localAttempts >= MAX_ATTEMPTS;
        }

        return false;
    }

    /**
     * Clears the lockout counter for the given email (DT 3.2.23).
     *
     * <p>This is the <strong>only</strong> sanctioned unlock path and must be
     * called exclusively after a successful password reset via email.</p>
     *
     * <p>Clears state from both Redis and all local caches to ensure
     * immediate unlock across all instances.</p>
     *
     * @param email the email whose lockout should be cleared
     */
    public void clearLockout(String email) {
        // Clear L1 cache
        lockoutStatusCache.invalidate(email);
        fallbackAttemptsCache.invalidate(email);

        // Clear Redis
        try {
            String key = KEY_PREFIX + email;
            redisTemplate.delete(key);
        } catch (Exception e) {
            log.debug("Redis unavailable for lockout clearing. Local caches cleared. Error: {}", e.getMessage());
        }

        log.info("Lockout cleared for account after password reset.");
    }
}
