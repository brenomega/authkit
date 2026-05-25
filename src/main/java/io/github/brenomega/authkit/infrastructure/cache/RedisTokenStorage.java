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

    private static final String PREFIX = "refresh:token:";
    private final StringRedisTemplate redisTemplate;

    public RedisTokenStorage(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @SuppressWarnings("null")
    @Override
    public void storeRefreshToken(String userId, String jti, String rawToken, long durationDays) {
        String hashedToken = hashToken(rawToken);
        String key = PREFIX + userId;
        long durationSeconds = Duration.ofDays(durationDays).getSeconds();

        // Extract token family ID from the raw token structure
        String familyId = RefreshTokenCodec.parse(rawToken)
                .map(RefreshTokenCodec.IssuedRefreshToken::familyId)
                .orElseThrow(() -> new IllegalArgumentException("Malformed refresh token"));

        String storedValue = hashedToken + ":" + familyId;

        String luaScript =
            "redis.call('HSET', KEYS[1], ARGV[1], ARGV[2]); " +
            "redis.call('EXPIRE', KEYS[1], ARGV[3]); " +
            "return true;";

        DefaultRedisScript<Boolean> script =
            new DefaultRedisScript<>(luaScript, Boolean.class);

        redisTemplate.execute(script, List.of(key), jti, storedValue, String.valueOf(durationSeconds));
    }

    @SuppressWarnings("null")
    @Override
    public boolean validateToken(String userId, String jti, String rawToken) {
        String key = PREFIX + userId;
        Object storedValObj = redisTemplate.opsForHash().get(key, jti);

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
    public boolean rotateRefreshToken(String userId, String currentJti, String currentRawToken,
                                      String nextJti, String nextRawToken, long durationDays) {
        String key = PREFIX + userId;
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

        // Lua Script for Atomic Token Rotation & Reuse Detection (DT 3.2.5)
        String luaScript = """
                local key = KEYS[1]
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

                    if stored_hash == current_hash then
                        -- Valid rotation: swap tokens, propagate token family
                        redis.call('HDEL', key, current_jti)
                        redis.call('HSET', key, next_jti, next_hash .. ":" .. stored_family)
                        redis.call('EXPIRE', key, duration_seconds)
                        return 1 -- Successful rotation
                    end
                end

                -- 2. Token mismatch or missing JTI. Check for reuse attack of the same family
                local all_fields = redis.call('HGETALL', key)
                local reuse_detected = false
                for i = 1, #all_fields, 2 do
                    local jti = all_fields[i]
                    local val = all_fields[i+1]
                    local colon_idx = string.find(val, ":")
                    if colon_idx then
                        local stored_family = string.sub(val, colon_idx + 1)
                        if stored_family == current_family_id then
                            reuse_detected = true
                        end
                    end
                end

                if reuse_detected then
                    -- Revoke all sessions sharing the compromised token family!
                    for i = 1, #all_fields, 2 do
                        local jti = all_fields[i]
                        local val = all_fields[i+1]
                        local colon_idx = string.find(val, ":")
                        if colon_idx then
                            local stored_family = string.sub(val, colon_idx + 1)
                            if stored_family == current_family_id then
                                redis.call('HDEL', key, jti)
                            end
                        end
                    end
                    return -1 -- Compromise detected & family fully revoked
                end

                return 0 -- Generic token invalidation
                """;

        DefaultRedisScript<Long> script = new DefaultRedisScript<>(luaScript, Long.class);

        Long result = redisTemplate.execute(
                script,
                List.of(key),
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
        String key = PREFIX + userId;
        return redisTemplate.opsForHash().keys(key).stream()
                .map(Object::toString)
                .toList();
    }

    @Override
    public void revokeSession(String userId, String jti) {
        String key = PREFIX + userId;
        redisTemplate.opsForHash().delete(key, jti);
    }

    @Override
    public void revokeAllSessions(String userId) {
        String key = PREFIX + userId;
        redisTemplate.delete(key);
    }

    @SuppressWarnings("null")
    @Override
    public void revokeOtherSessions(String userId, String currentJti) {
        String key = PREFIX + userId;
        String luaScript = """
                local fields = redis.call('HKEYS', KEYS[1])
                for i = 1, #fields do
                    if fields[i] ~= ARGV[1] then
                        redis.call('HDEL', KEYS[1], fields[i])
                    end
                end
                return #fields
                """;

        DefaultRedisScript<Long> script = new DefaultRedisScript<>(luaScript, Long.class);
        redisTemplate.execute(script, List.of(key), currentJti);
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
        String luaScript = """
                local stored = redis.call('GET', KEYS[1])
                if not stored then
                    return 0
                end
                if stored == ARGV[1] then
                    redis.call('DEL', KEYS[1])
                    return 1
                end
                return 0
                """;

        DefaultRedisScript<Long> script =
                new DefaultRedisScript<>(luaScript, Long.class);

        Long consumed = redisTemplate.execute(script, List.of(key), inputHash);
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
        String luaScript = """
                local stored = redis.call('GET', KEYS[1])
                if not stored then
                    return 0
                end
                if stored == ARGV[1] then
                    redis.call('DEL', KEYS[1])
                    return 1
                end
                return 0
                """;

        DefaultRedisScript<Long> script =
                new DefaultRedisScript<>(luaScript, Long.class);

        Long consumed = redisTemplate.execute(script, List.of(key), inputHash);
        return consumed != null && consumed == 1L;
    }

    private String hashToken(String rawToken) {
        return TokenHasher.sha256Hex(rawToken);
    }
}
