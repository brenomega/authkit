package io.github.brenomega.authkit.infrastructure.cache;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.List;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.exception.TokenFamilyCompromisedException;
import io.github.brenomega.authkit.service.spi.TokenStorage;

/**
 * Implementation of TokenStorage utilizing Spring Data Redis.
 *
 * <p>Implements Token Family Tracking and Reuse Detection (DT 3.2.5) via atomic
 * Lua scripts to prevent session replay attacks.</p>
 */
@Component
public class RedisTokenStorage implements TokenStorage {

    private static final String TOKEN_KEY_SUFFIX = ":tokens";
    private static final String FAMILY_KEY_SUFFIX = ":family:";
    private static final String FAMILIES_KEY_SUFFIX = ":families";
    private static final DefaultRedisScript<Boolean> STORE_REFRESH_SCRIPT =
            new DefaultRedisScript<>("""
                    redis.call('HSET', KEYS[1], ARGV[1], ARGV[2]);
                    redis.call('EXPIRE', KEYS[1], ARGV[3]);
                    redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[3]);
                    redis.call('SADD', KEYS[3], ARGV[4]);
                    redis.call('EXPIRE', KEYS[3], ARGV[3]);
                    return true;
                    """, Boolean.class);
    private static final DefaultRedisScript<Long> ROTATE_REFRESH_SCRIPT =
            new DefaultRedisScript<>("""
                    local key = KEYS[1]
                    local family_key = KEYS[2]
                    local families_key = KEYS[3]
                    local current_jti = ARGV[1]
                    local current_hash = ARGV[2]
                    local next_jti = ARGV[3]
                    local next_hash = ARGV[4]
                    local duration_seconds = ARGV[5]
                    local current_family_id = ARGV[6]

                    -- 1. Check if the current JTI exists
                    local stored = redis.call('HGET', key, current_jti)
                    if stored then
                        local colon_idx = string.find(stored, ":")
                        local stored_hash = stored
                        local stored_family = "unknown-family"
                        if colon_idx then
                            stored_hash = string.sub(stored, 1, colon_idx - 1)
                            stored_family = string.sub(stored, colon_idx + 1)
                        end

                        if stored_hash == current_hash and stored_family == current_family_id then
                            -- Valid rotation: swap tokens, propagate token family
                            redis.call('HDEL', key, current_jti)
                            redis.call('HSET', key, next_jti, next_hash .. ":" .. stored_family)
                            redis.call('EXPIRE', key, duration_seconds)
                            redis.call('SET', family_key, next_jti, 'EX', duration_seconds)
                            redis.call('SADD', families_key, stored_family)
                            redis.call('EXPIRE', families_key, duration_seconds)
                            return 1 -- Successful rotation
                        end
                    end

                    -- 2. Token mismatch or missing JTI. A live family pointer means
                    -- the family has moved forward and this token is a replay.
                    local active_jti = redis.call('GET', family_key)
                    if active_jti then
                        redis.call('HDEL', key, active_jti)
                        redis.call('HDEL', key, current_jti)
                        redis.call('DEL', family_key)
                        redis.call('SREM', families_key, current_family_id)
                        return -1 -- Compromise detected and family fully revoked
                    end

                    return 0 -- Generic token invalidation
                    """, Long.class);
    private static final DefaultRedisScript<Long> REVOKE_OTHER_SESSIONS_SCRIPT =
            new DefaultRedisScript<>("""
                    local family_key_prefix = ARGV[2]
                    local fields = redis.call('HKEYS', KEYS[1])
                    local removed = 0
                    for i = 1, #fields do
                        if fields[i] ~= ARGV[1] then
                            local stored = redis.call('HGET', KEYS[1], fields[i])
                            redis.call('HDEL', KEYS[1], fields[i])
                            removed = removed + 1
                            if stored then
                                local colon_idx = string.find(stored, ":")
                                if colon_idx then
                                    local stored_family = string.sub(stored, colon_idx + 1)
                                    redis.call('DEL', family_key_prefix .. stored_family)
                                    redis.call('SREM', KEYS[2], stored_family)
                                end
                            end
                        end
                    end
                    return removed
                    """, Long.class);
    private static final DefaultRedisScript<Long> REVOKE_SESSION_SCRIPT =
            new DefaultRedisScript<>("""
                    local stored = redis.call('HGET', KEYS[1], ARGV[1])
                    if not stored then
                        return 0
                    end
                    redis.call('HDEL', KEYS[1], ARGV[1])
                    local colon_idx = string.find(stored, ":")
                    if colon_idx then
                        local stored_family = string.sub(stored, colon_idx + 1)
                        redis.call('DEL', ARGV[2] .. stored_family)
                        redis.call('SREM', KEYS[2], stored_family)
                    end
                    return 1
                    """, Long.class);
    private static final DefaultRedisScript<Long> REVOKE_ALL_SESSIONS_SCRIPT =
            new DefaultRedisScript<>("""
                    local families = redis.call('SMEMBERS', KEYS[2])
                    for i = 1, #families do
                        redis.call('DEL', ARGV[1] .. families[i])
                    end
                    redis.call('DEL', KEYS[1])
                    redis.call('DEL', KEYS[2])
                    return #families
                    """, Long.class);
    private static final DefaultRedisScript<Long> CONSUME_VALUE_SCRIPT =
            new DefaultRedisScript<>("""
                    local stored = redis.call('GET', KEYS[1])
                    if not stored then
                        return 0
                    end
                    if stored == ARGV[1] then
                        redis.call('DEL', KEYS[1])
                        return 1
                    end
                    return 0
                    """, Long.class);
    private final StringRedisTemplate redisTemplate;

    public RedisTokenStorage(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @SuppressWarnings("null")
    @Override
    public void storeRefreshToken(String userId, String jti, String rawToken, long durationDays) {
        String hashedToken = hashToken(rawToken);
        long durationSeconds = Duration.ofDays(durationDays).getSeconds();

        // Extract token family ID from the raw token structure
        String familyId = RefreshTokenCodec.parse(rawToken)
                .map(RefreshTokenCodec.IssuedRefreshToken::familyId)
                .orElseThrow(() -> new IllegalArgumentException("Malformed refresh token"));

        String storedValue = hashedToken + ":" + familyId;

        redisTemplate.execute(
                STORE_REFRESH_SCRIPT,
                List.of(tokenKey(userId), familyKey(userId, familyId), familiesKey(userId)),
                jti,
                storedValue,
                String.valueOf(durationSeconds),
                familyId);
    }

    @SuppressWarnings("null")
    @Override
    public boolean validateToken(String userId, String jti, String rawToken) {
        Object storedValObj = redisTemplate.opsForHash().get(tokenKey(userId), jti);

        if (storedValObj == null) {
            return false;
        }

        String storedVal = (String) storedValObj;
        String storedHash = storedVal;
        int colonIdx = storedVal.indexOf(':');
        if (colonIdx != -1) {
            storedHash = storedVal.substring(0, colonIdx);
        }

        String inputHash = hashToken(rawToken);

        // DT 3.2.13: Preventing Side-Channel Timing Attacks using constant-time comparison
        return MessageDigest.isEqual(
                storedHash.getBytes(StandardCharsets.UTF_8),
                inputHash.getBytes(StandardCharsets.UTF_8)
        );
    }

    @SuppressWarnings("null")
    @Override
    public boolean isSessionActive(String userId, String jti) {
        if (userId == null || userId.isBlank() || jti == null || jti.isBlank()) {
            return false;
        }
        return redisTemplate.opsForHash().get(tokenKey(userId), jti) != null;
    }

    @SuppressWarnings("null")
    @Override
    public boolean rotateRefreshToken(String userId, String currentJti, String currentRawToken,
                                      String nextJti, String nextRawToken, long durationDays) {
        String currentHash = hashToken(currentRawToken);
        String nextHash = hashToken(nextRawToken);
        long durationSeconds = Duration.ofDays(durationDays).getSeconds();

        RefreshTokenCodec.IssuedRefreshToken currentToken = RefreshTokenCodec.parse(currentRawToken)
                .orElse(null);
        RefreshTokenCodec.IssuedRefreshToken nextToken = RefreshTokenCodec.parse(nextRawToken)
                .orElse(null);

        if (currentToken == null
                || nextToken == null
                || !userId.equals(currentToken.userId())
                || !userId.equals(nextToken.userId())
                || !currentJti.equals(currentToken.jti())
                || !nextJti.equals(nextToken.jti())
                || !currentToken.familyId().equals(nextToken.familyId())) {
            return false;
        }

        String currentFamilyId = currentToken.familyId();

        Long result = redisTemplate.execute(
                ROTATE_REFRESH_SCRIPT,
                List.of(tokenKey(userId), familyKey(userId, currentFamilyId), familiesKey(userId)),
                currentJti,
                currentHash,
                nextJti,
                nextHash,
                String.valueOf(durationSeconds),
                currentFamilyId
        );

        if (result != null && result == -1L) {
            throw new TokenFamilyCompromisedException();
        }

        return result != null && result == 1L;
    }

    @Override
    public java.util.List<String> listSessions(String userId) {
        return redisTemplate.opsForHash().keys(tokenKey(userId)).stream()
                .map(Object::toString)
                .toList();
    }

    @SuppressWarnings("null")
    @Override
    public void revokeSession(String userId, String jti) {
        redisTemplate.execute(
                REVOKE_SESSION_SCRIPT,
                List.of(tokenKey(userId), familiesKey(userId)),
                jti,
                familyKeyPrefix(userId));
    }

    @SuppressWarnings("null")
    @Override
    public void revokeAllSessions(String userId) {
        redisTemplate.execute(
                REVOKE_ALL_SESSIONS_SCRIPT,
                List.of(tokenKey(userId), familiesKey(userId)),
                familyKeyPrefix(userId));
    }

    @SuppressWarnings("null")
    @Override
    public void revokeOtherSessions(String userId, String currentJti) {
        redisTemplate.execute(
                REVOKE_OTHER_SESSIONS_SCRIPT,
                List.of(tokenKey(userId), familiesKey(userId)),
                currentJti,
                familyKeyPrefix(userId));
    }

    @SuppressWarnings("null")
    @Override
    public void storeRecoveryToken(String email, String rawToken, long durationMinutes) {
        String hashedToken = hashToken(rawToken);
        String key = "recovery:token:" + email;
        redisTemplate.opsForValue().set(key, hashedToken, Duration.ofMinutes(durationMinutes));
    }

    @Override
    public boolean validateRecoveryToken(String email, String rawToken) {
        String key = "recovery:token:" + email;
        String storedHash = redisTemplate.opsForValue().get(key);

        if (storedHash == null) {
            return false;
        }

        String inputHash = hashToken(rawToken);
        return MessageDigest.isEqual(
                storedHash.getBytes(StandardCharsets.UTF_8),
                inputHash.getBytes(StandardCharsets.UTF_8)
        );
    }

    @SuppressWarnings("null")
    @Override
    public boolean consumeRecoveryToken(String email, String rawToken) {
        String key = "recovery:token:" + email;
        String inputHash = hashToken(rawToken);

        Long consumed = redisTemplate.execute(CONSUME_VALUE_SCRIPT, List.of(key), inputHash);
        return consumed != null && consumed == 1L;
    }

    @Override
    public void revokeRecoveryToken(String email) {
        String key = "recovery:token:" + email;
        redisTemplate.delete(key);
    }

    @SuppressWarnings("null")
    @Override
    public void storeMfaChallenge(String userId, String jti, String rawToken, long durationMinutes) {
        String key = "mfa:challenge:" + userId + ":" + jti;
        redisTemplate.opsForValue().set(key, hashToken(rawToken), Duration.ofMinutes(durationMinutes));
    }

    @SuppressWarnings("null")
    @Override
    public boolean consumeMfaChallenge(String userId, String jti, String rawToken) {
        String key = "mfa:challenge:" + userId + ":" + jti;
        String inputHash = hashToken(rawToken);

        Long consumed = redisTemplate.execute(CONSUME_VALUE_SCRIPT, List.of(key), inputHash);
        return consumed != null && consumed == 1L;
    }

    private String hashToken(String rawToken) {
        return TokenHasher.sha256Hex(rawToken);
    }

    private String tokenKey(String userId) {
        return hashTaggedPrefix(userId) + TOKEN_KEY_SUFFIX;
    }

    private String familyKey(String userId, String familyId) {
        return familyKeyPrefix(userId) + familyId;
    }

    private String familyKeyPrefix(String userId) {
        return hashTaggedPrefix(userId) + FAMILY_KEY_SUFFIX;
    }

    private String familiesKey(String userId) {
        return hashTaggedPrefix(userId) + FAMILIES_KEY_SUFFIX;
    }

    private String hashTaggedPrefix(String userId) {
        return "refresh:{" + userId + "}";
    }
}
