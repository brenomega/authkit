package io.github.brenomega.authkit.infrastructure.cache;

import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import io.lettuce.core.ScanArgs;
import io.lettuce.core.ScanCursor;
import io.lettuce.core.api.async.RedisHashAsyncCommands;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.stereotype.Component;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.domain.user.util.RefreshTokenCodec;
import io.github.brenomega.authkit.exception.TokenFamilyCompromisedException;
import io.github.brenomega.authkit.exception.InvalidSessionCursorException;
import io.github.brenomega.authkit.infrastructure.audit.AuditDigestService;
import io.github.brenomega.authkit.service.spi.SessionPage;
import io.github.brenomega.authkit.service.spi.SessionMetadata;
import io.github.brenomega.authkit.service.spi.TokenStorage;

/**
 * Implementation of TokenStorage utilizing Spring Data Redis.
 *
 * <p>Implements Token Family Tracking and Reuse Detection (DT 3.2.5) via atomic
 * Lua scripts to prevent session replay attacks.</p>
 */
@Component
@ConditionalOnProperty(prefix = "authkit.auth.token-storage", name = "backend",
        havingValue = "redis", matchIfMissing = true)
public class RedisTokenStorage implements TokenStorage {

    private static final String TOKEN_KEY_SUFFIX = ":tokens";
    private static final String FAMILY_KEY_SUFFIX = ":family:";
    private static final String FAMILIES_KEY_SUFFIX = ":families";
    private static final String SESSION_METADATA_KEY_SUFFIX = ":session-metadata";
    private static final String SESSION_PUBLIC_INDEX_KEY_SUFFIX = ":session-public-index";
    private static final String SESSION_CURSOR_PREFIX = "session:cursor:";
    private static final Duration SESSION_CURSOR_TTL = Duration.ofMinutes(5);
    private static final DefaultRedisScript<Boolean> STORE_REFRESH_SCRIPT =
            new DefaultRedisScript<>("""
                    redis.call('HSET', KEYS[1], ARGV[1], ARGV[2]);
                    redis.call('EXPIRE', KEYS[1], ARGV[3]);
                    redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[3]);
                    redis.call('SADD', KEYS[3], ARGV[4]);
                    redis.call('EXPIRE', KEYS[3], ARGV[3]);
                    redis.call('HSET', KEYS[4], ARGV[1], ARGV[5]);
                    redis.call('EXPIRE', KEYS[4], ARGV[3]);
                    redis.call('HSET', KEYS[5], ARGV[6], ARGV[1]);
                    redis.call('EXPIRE', KEYS[5], ARGV[3]);
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
                    local seen_at = ARGV[7]
                    local expires_at = ARGV[8]

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
                            local metadata = redis.call('HGET', KEYS[4], current_jti)
                            if metadata then
                                local updated_metadata = string.gsub(metadata,
                                    '^([^|]+)|([^|]+)|[^|]+|[^|]+|',
                                    '%1|%2|' .. seen_at .. '|' .. expires_at .. '|', 1)
                                redis.call('HDEL', KEYS[4], current_jti)
                                redis.call('HSET', KEYS[4], next_jti, updated_metadata)
                                local public_id = string.match(updated_metadata, '^([^|]+)|')
                                if public_id then redis.call('HSET', KEYS[5], public_id, next_jti) end
                            end
                            redis.call('EXPIRE', key, duration_seconds)
                            redis.call('EXPIRE', KEYS[4], duration_seconds)
                            redis.call('EXPIRE', KEYS[5], duration_seconds)
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
                        local active_metadata = redis.call('HGET', KEYS[4], active_jti)
                        local current_metadata = redis.call('HGET', KEYS[4], current_jti)
                        for _, metadata in ipairs({active_metadata, current_metadata}) do
                            if metadata then
                                local public_id = string.match(metadata, '^([^|]+)|')
                                if public_id then redis.call('HDEL', KEYS[5], public_id) end
                            end
                        end
                        redis.call('HDEL', KEYS[4], active_jti)
                        redis.call('HDEL', KEYS[4], current_jti)
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
                            local metadata = redis.call('HGET', KEYS[3], fields[i])
                            if metadata then
                                local public_id = string.match(metadata, '^([^|]+)|')
                                if public_id then redis.call('HDEL', KEYS[4], public_id) end
                            end
                            redis.call('HDEL', KEYS[3], fields[i])
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
                    local metadata = redis.call('HGET', KEYS[3], ARGV[1])
                    if metadata then
                        local public_id = string.match(metadata, '^([^|]+)|')
                        if public_id then redis.call('HDEL', KEYS[4], public_id) end
                    end
                    redis.call('HDEL', KEYS[3], ARGV[1])
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
                    redis.call('DEL', KEYS[3])
                    redis.call('DEL', KEYS[4])
                    return #families
                    """, Long.class);
    private static final DefaultRedisScript<Long> REVOKE_PUBLIC_SESSION_SCRIPT =
            new DefaultRedisScript<>("""
                    local jti = redis.call('HGET', KEYS[4], ARGV[1])
                    if not jti then return 0 end
                    local stored = redis.call('HGET', KEYS[1], jti)
                    redis.call('HDEL', KEYS[1], jti)
                    redis.call('HDEL', KEYS[3], jti)
                    redis.call('HDEL', KEYS[4], ARGV[1])
                    if stored then
                        local colon_idx = string.find(stored, ':')
                        if colon_idx then
                            local family = string.sub(stored, colon_idx + 1)
                            redis.call('DEL', ARGV[2] .. family)
                            redis.call('SREM', KEYS[2], family)
                        end
                    end
                    return 1
                    """, Long.class);
    private static final DefaultRedisScript<Long> TOUCH_SESSION_SCRIPT =
            new DefaultRedisScript<>("""
                    local current = redis.call('HGET', KEYS[1], ARGV[1])
                    if not current or current ~= ARGV[2] then return 0 end
                    redis.call('HSET', KEYS[1], ARGV[1], ARGV[3])
                    return 1
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
    private static final DefaultRedisScript<Long> CLAIM_RECOVERY_SCRIPT =
            new DefaultRedisScript<>("""
                    local stored = redis.call('GET', KEYS[1])
                    if not stored or stored ~= ARGV[1] then
                        return 0
                    end
                    local claimed = redis.call('SET', KEYS[2], ARGV[2], 'NX', 'EX', ARGV[3])
                    if claimed then return 1 end
                    return 0
                    """, Long.class);
    private static final DefaultRedisScript<Long> COMPLETE_RECOVERY_CLAIM_SCRIPT =
            new DefaultRedisScript<>("""
                    if redis.call('GET', KEYS[2]) ~= ARGV[1] then return 0 end
                    redis.call('DEL', KEYS[1])
                    redis.call('DEL', KEYS[2])
                    return 1
                    """, Long.class);
    private static final DefaultRedisScript<Long> RELEASE_RECOVERY_CLAIM_SCRIPT =
            new DefaultRedisScript<>("""
                    if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
                    redis.call('DEL', KEYS[1])
                    return 1
                    """, Long.class);
    private final StringRedisTemplate redisTemplate;
    private final AuditDigestService auditDigestService;

    public RedisTokenStorage(StringRedisTemplate redisTemplate, AuditDigestService auditDigestService) {
        this.redisTemplate = redisTemplate;
        this.auditDigestService = auditDigestService;
    }

    @SuppressWarnings("null")
    @Override
    public void storeRefreshToken(String userId, String jti, String rawToken, long durationDays,
                                  SessionMetadata metadata) {
        String hashedToken = hashToken(rawToken);
        long durationSeconds = Duration.ofDays(durationDays).getSeconds();

        // Extract token family ID from the raw token structure
        String familyId = RefreshTokenCodec.parse(rawToken)
                .map(RefreshTokenCodec.IssuedRefreshToken::familyId)
                .orElseThrow(() -> new IllegalArgumentException("Malformed refresh token"));

        String storedValue = hashedToken + ":" + familyId;
        if (metadata == null || !jti.equals(metadata.jti())) {
            throw new IllegalArgumentException("Session metadata does not match storage key");
        }

        redisTemplate.execute(
                STORE_REFRESH_SCRIPT,
                List.of(tokenKey(userId), familyKey(userId, familyId), familiesKey(userId),
                        sessionMetadataKey(userId), sessionPublicIndexKey(userId)),
                jti,
                storedValue,
                String.valueOf(durationSeconds),
                familyId,
                serializeMetadata(metadata),
                metadata.publicSessionId());
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
                List.of(tokenKey(userId), familyKey(userId, currentFamilyId), familiesKey(userId),
                        sessionMetadataKey(userId), sessionPublicIndexKey(userId)),
                currentJti,
                currentHash,
                nextJti,
                nextHash,
                String.valueOf(durationSeconds),
                currentFamilyId,
                Long.toString(Instant.now().getEpochSecond()),
                Long.toString(Instant.now().plusSeconds(durationSeconds).getEpochSecond())
        );

        if (result != null && result == -1L) {
            throw new TokenFamilyCompromisedException();
        }

        return result != null && result == 1L;
    }

    @SuppressWarnings("null")
    @Override
    public SessionPage listSessions(String userId, int limit, String cursor) {
        if (limit < 1 || limit > 100) {
            throw new InvalidSessionCursorException();
        }

        CursorState state = cursor == null || cursor.isBlank()
                ? new CursorState(userId, "0", List.of())
                : consumeCursor(userId, cursor);
        List<String> itemJtis = new ArrayList<>(limit);
        List<String> overflow = new ArrayList<>(state.overflow());
        while (!overflow.isEmpty() && itemJtis.size() < limit) {
            itemJtis.add(overflow.remove(0));
        }

        String redisCursor = state.redisCursor();
        boolean needsInitialScan = cursor == null || cursor.isBlank();
        int scanBudget = Math.max(16, limit * 4);
        while (itemJtis.size() < limit && scanBudget-- > 0
                && (needsInitialScan || !"0".equals(redisCursor))) {
            needsInitialScan = false;
            HashScanResult scan = scanHash(tokenKey(userId), redisCursor, Math.max(1, limit - itemJtis.size()));
            redisCursor = scan.nextCursor();
            for (String jti : scan.fields()) {
                if (itemJtis.size() < limit) {
                    itemJtis.add(jti);
                } else {
                    overflow.add(jti);
                }
            }
        }

        String nextCursor = null;
        if (!"0".equals(redisCursor) || !overflow.isEmpty()) {
            nextCursor = storeCursor(new CursorState(userId, redisCursor, overflow));
        }
        List<SessionMetadata> items = itemJtis.stream()
                .map(jti -> readOrBackfillMetadata(userId, jti))
                .toList();
        return new SessionPage(items, nextCursor);
    }

    @SuppressWarnings("null")
    private HashScanResult scanHash(String key, String cursor, int count) {
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] cursorBytes = cursor.getBytes(StandardCharsets.UTF_8);
        byte[] countBytes = Integer.toString(count).getBytes(StandardCharsets.UTF_8);
        HashScanResult result = redisTemplate.execute((RedisCallback<HashScanResult>) connection -> {
            HashScanResult lettuceResult = scanHashWithNativeLettuce(
                    connection.getNativeConnection(),
                    keyBytes,
                    cursor,
                    count);
            if (lettuceResult != null) {
                return lettuceResult;
            }
            Object raw = connection.execute(
                    "HSCAN",
                    keyBytes,
                    cursorBytes,
                    "COUNT".getBytes(StandardCharsets.UTF_8),
                    countBytes);
            return parseHashScanResponse(raw);
        });
        return result == null ? new HashScanResult("0", List.of()) : result;
    }

    @SuppressWarnings("unchecked")
    private static HashScanResult scanHashWithNativeLettuce(Object nativeConnection,
                                                           byte[] key,
                                                           String cursor,
                                                           int count) {
        ScanCursor scanCursor = ScanCursor.of(cursor);
        ScanArgs args = new ScanArgs().limit(count);
        try {
            if (nativeConnection instanceof RedisHashAsyncCommands<?, ?> hashCommands) {
                var commands = (RedisHashAsyncCommands<byte[], byte[]>) hashCommands;
                return parseHashScanResponse(commands.hscan(key, scanCursor, args).get());
            }
        } catch (ClassCastException | ExecutionException ex) {
            return null;
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return null;
        }
        return null;
    }

    static HashScanResult parseHashScanResponse(Object raw) {
        HashScanResult cursorLike = parseCursorLikeResponse(raw);
        if (cursorLike != null) {
            return cursorLike;
        }
        List<?> response = toList(raw);
        if (response.size() != 2) {
            return new HashScanResult("0", List.of());
        }
        String next = decode(response.get(0));
        List<String> fields = new ArrayList<>();
        if (response.get(1) instanceof Map<?, ?> map) {
            for (Object key : map.keySet()) {
                fields.add(decode(key));
            }
        } else {
            List<?> entries = toList(response.get(1));
            boolean parsedEntryObjects = false;
            for (Object entry : entries) {
                Object key = extractEntryKey(entry);
                if (key != null) {
                    fields.add(decode(key));
                    parsedEntryObjects = true;
                }
            }
            if (!parsedEntryObjects) {
                for (int i = 0; i + 1 < entries.size(); i += 2) {
                    fields.add(decode(entries.get(i)));
                }
            }
        }
        return new HashScanResult(next, fields);
    }

    private static HashScanResult parseCursorLikeResponse(Object raw) {
        Object cursor = invokeNoArg(raw, "getCursor");
        Object map = invokeNoArg(raw, "getMap");
        if (cursor != null && map instanceof Map<?, ?> hashEntries) {
            List<String> fields = new ArrayList<>();
            for (Object key : hashEntries.keySet()) {
                fields.add(decode(key));
            }
            return new HashScanResult(decode(cursor), fields);
        }

        Object keys = invokeNoArg(raw, "getKeys");
        if (cursor != null && keys != null) {
            List<String> fields = new ArrayList<>();
            for (Object key : toList(keys)) {
                fields.add(decode(key));
            }
            return new HashScanResult(decode(cursor), fields);
        }
        return null;
    }

    private static Object extractEntryKey(Object entry) {
        if (entry instanceof Map.Entry<?, ?> mapEntry) {
            return mapEntry.getKey();
        }
        return invokeNoArg(entry, "getKey");
    }

    private static Object invokeNoArg(Object target, String methodName) {
        if (target == null) {
            return null;
        }
        try {
            Method method = target.getClass().getMethod(methodName);
            method.setAccessible(true);
            return method.invoke(target);
        } catch (ReflectiveOperationException ex) {
            return null;
        }
    }

    private static List<?> toList(Object value) {
        if (value == null) {
            return List.of();
        }
        if (value instanceof List<?> list) {
            return list;
        }
        if (value instanceof Iterable<?> iterable) {
            List<Object> values = new ArrayList<>();
            for (Object item : iterable) {
                values.add(item);
            }
            return values;
        }
        if (value.getClass().isArray() && !(value instanceof byte[])) {
            List<Object> values = new ArrayList<>();
            int length = Array.getLength(value);
            for (int index = 0; index < length; index++) {
                values.add(Array.get(value, index));
            }
            return values;
        }
        return List.of();
    }

    private static String decode(Object value) {
        if (value instanceof byte[] bytes) {
            return new String(bytes, StandardCharsets.UTF_8);
        }
        if (value instanceof ByteBuffer buffer) {
            ByteBuffer copy = buffer.asReadOnlyBuffer();
            byte[] bytes = new byte[copy.remaining()];
            copy.get(bytes);
            return new String(bytes, StandardCharsets.UTF_8);
        }
        return String.valueOf(value);
    }

    private CursorState consumeCursor(String userId, String token) {
        String serialized = redisTemplate.opsForValue().getAndDelete(SESSION_CURSOR_PREFIX + token);
        if (serialized == null) {
            throw new InvalidSessionCursorException();
        }
        String[] parts = serialized.split("\\n", -1);
        if (parts.length != 3 || !MessageDigest.isEqual(
                userId.getBytes(StandardCharsets.UTF_8), parts[0].getBytes(StandardCharsets.UTF_8))) {
            throw new InvalidSessionCursorException();
        }
        List<String> overflow = parts[2].isBlank() ? List.of() : Arrays.asList(parts[2].split(","));
        return new CursorState(parts[0], parts[1], overflow);
    }

    @SuppressWarnings("null")
    private String storeCursor(CursorState state) {
        String token = io.github.brenomega.authkit.domain.user.util.SecureTokenGenerator.randomUrlSafeToken(24);
        String serialized = state.userId() + "\n" + state.redisCursor() + "\n"
                + String.join(",", state.overflow());
        redisTemplate.opsForValue().set(SESSION_CURSOR_PREFIX + token, serialized, SESSION_CURSOR_TTL);
        return token;
    }

    private record CursorState(String userId, String redisCursor, List<String> overflow) {
    }

    record HashScanResult(String nextCursor, List<String> fields) {
    }

    @SuppressWarnings("null")
    @Override
    public void revokeSession(String userId, String publicSessionId) {
        redisTemplate.execute(
                REVOKE_PUBLIC_SESSION_SCRIPT,
                List.of(tokenKey(userId), familiesKey(userId), sessionMetadataKey(userId),
                        sessionPublicIndexKey(userId)),
                publicSessionId,
                familyKeyPrefix(userId));
    }

    @Override
    public void revokeSessionByJti(String userId, String jti) {
        redisTemplate.execute(
                REVOKE_SESSION_SCRIPT,
                List.of(tokenKey(userId), familiesKey(userId), sessionMetadataKey(userId),
                        sessionPublicIndexKey(userId)),
                jti,
                familyKeyPrefix(userId));
    }

    @Override
    public void touchSession(String userId, String jti, Instant seenAt, String maskedIp, long throttleSeconds) {
        Object raw = redisTemplate.opsForHash().get(sessionMetadataKey(userId), jti);
        if (!(raw instanceof String serialized)) {
            return;
        }
        SessionMetadata current = deserializeMetadata(jti, serialized);
        if (current.lastSeenAt().isAfter(seenAt.minusSeconds(throttleSeconds))) {
            return;
        }
        SessionMetadata updated = new SessionMetadata(
                current.publicSessionId(), jti, current.createdAt(), seenAt, current.expiresAt(),
                current.initialAmr(), current.userAgentSummary(), current.deviceLabel(),
                current.creationIpMasked(), maskedIp);
        redisTemplate.execute(TOUCH_SESSION_SCRIPT, List.of(sessionMetadataKey(userId)),
                jti, serialized, serializeMetadata(updated));
    }

    @SuppressWarnings("null")
    @Override
    public void revokeAllSessions(String userId) {
        redisTemplate.execute(
                REVOKE_ALL_SESSIONS_SCRIPT,
                List.of(tokenKey(userId), familiesKey(userId), sessionMetadataKey(userId),
                        sessionPublicIndexKey(userId)),
                familyKeyPrefix(userId));
    }

    @SuppressWarnings("null")
    @Override
    public void revokeOtherSessions(String userId, String currentJti) {
        redisTemplate.execute(
                REVOKE_OTHER_SESSIONS_SCRIPT,
                List.of(tokenKey(userId), familiesKey(userId), sessionMetadataKey(userId),
                        sessionPublicIndexKey(userId)),
                currentJti,
                familyKeyPrefix(userId));
    }

    @SuppressWarnings("null")
    @Override
    public void storeRecoveryToken(String email, String rawToken, long durationMinutes) {
        String hashedToken = hashToken(rawToken);
        String key = recoveryTokenKey(email);
        redisTemplate.opsForValue().set(key, hashedToken, Duration.ofMinutes(durationMinutes));
        redisTemplate.delete(recoveryClaimKey(email));
    }

    @Override
    public boolean validateRecoveryToken(String email, String rawToken) {
        String key = recoveryTokenKey(email);
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
        String key = recoveryTokenKey(email);
        String inputHash = hashToken(rawToken);

        Long consumed = redisTemplate.execute(CONSUME_VALUE_SCRIPT, List.of(key), inputHash);
        return consumed != null && consumed == 1L;
    }

    @Override
    public boolean claimRecoveryToken(String email, String rawToken, String claimId, long claimTtlSeconds) {
        Long claimed = redisTemplate.execute(
                CLAIM_RECOVERY_SCRIPT,
                List.of(recoveryTokenKey(email), recoveryClaimKey(email)),
                hashToken(rawToken), claimId, Long.toString(claimTtlSeconds));
        return claimed != null && claimed == 1L;
    }

    @Override
    public void completeRecoveryTokenClaim(String email, String claimId) {
        redisTemplate.execute(
                COMPLETE_RECOVERY_CLAIM_SCRIPT,
                List.of(recoveryTokenKey(email), recoveryClaimKey(email)),
                claimId);
    }

    @Override
    public void releaseRecoveryTokenClaim(String email, String claimId) {
        redisTemplate.execute(
                RELEASE_RECOVERY_CLAIM_SCRIPT,
                List.of(recoveryClaimKey(email)),
                claimId);
    }

    @Override
    public void revokeRecoveryToken(String email) {
        String key = recoveryTokenKey(email);
        redisTemplate.delete(key);
        redisTemplate.delete(recoveryClaimKey(email));
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

    private String recoveryTokenKey(String email) {
        String normalizedEmail = EmailNormalizer.normalize(email);
        return "recovery:token:" + auditDigestService.hmacHex(normalizedEmail);
    }

    private String recoveryClaimKey(String email) {
        String normalizedEmail = EmailNormalizer.normalize(email);
        return "recovery:claim:" + auditDigestService.hmacHex(normalizedEmail);
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

    private String sessionMetadataKey(String userId) {
        return hashTaggedPrefix(userId) + SESSION_METADATA_KEY_SUFFIX;
    }

    private String sessionPublicIndexKey(String userId) {
        return hashTaggedPrefix(userId) + SESSION_PUBLIC_INDEX_KEY_SUFFIX;
    }

    private SessionMetadata readOrBackfillMetadata(String userId, String jti) {
        Object raw = redisTemplate.opsForHash().get(sessionMetadataKey(userId), jti);
        if (raw instanceof String serialized) {
            return deserializeMetadata(jti, serialized);
        }
        Instant now = Instant.now();
        Long ttl = redisTemplate.getExpire(tokenKey(userId));
        long seconds = ttl == null || ttl < 1 ? 1 : ttl;
        SessionMetadata metadata = new SessionMetadata(
                java.util.UUID.randomUUID().toString(), jti, now, now, now.plusSeconds(seconds),
                List.of(), "Unknown client", null, "unknown", "unknown");
        redisTemplate.opsForHash().put(sessionMetadataKey(userId), jti, serializeMetadata(metadata));
        redisTemplate.opsForHash().put(sessionPublicIndexKey(userId), metadata.publicSessionId(), jti);
        redisTemplate.expire(sessionMetadataKey(userId), Duration.ofSeconds(seconds));
        redisTemplate.expire(sessionPublicIndexKey(userId), Duration.ofSeconds(seconds));
        return metadata;
    }

    private String serializeMetadata(SessionMetadata metadata) {
        return String.join("|",
                metadata.publicSessionId(),
                Long.toString(metadata.createdAt().getEpochSecond()),
                Long.toString(metadata.lastSeenAt().getEpochSecond()),
                Long.toString(metadata.expiresAt().getEpochSecond()),
                encode(String.join(" ", metadata.initialAmr())),
                encode(metadata.userAgentSummary()),
                encode(metadata.deviceLabel()),
                encode(metadata.creationIpMasked()),
                encode(metadata.lastIpMasked()));
    }

    private SessionMetadata deserializeMetadata(String jti, String serialized) {
        String[] parts = serialized.split("\\|", -1);
        if (parts.length != 9) {
            throw new IllegalStateException("Malformed session metadata");
        }
        String amr = decodeMetadata(parts[4]);
        return new SessionMetadata(
                parts[0], jti, Instant.ofEpochSecond(Long.parseLong(parts[1])),
                Instant.ofEpochSecond(Long.parseLong(parts[2])), Instant.ofEpochSecond(Long.parseLong(parts[3])),
                amr.isBlank() ? List.of() : List.of(amr.split(" ")),
                decodeMetadata(parts[5]), nullableDecode(parts[6]),
                decodeMetadata(parts[7]), decodeMetadata(parts[8]));
    }

    private String encode(String value) {
        if (value == null) {
            return "";
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private String decodeMetadata(String value) {
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }

    private String nullableDecode(String value) {
        return value.isEmpty() ? null : decodeMetadata(value);
    }

    private String hashTaggedPrefix(String userId) {
        return "refresh:{" + userId + "}";
    }
}
