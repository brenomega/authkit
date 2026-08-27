package io.github.brenomega.authkit.config;

import org.mockito.Mockito;
import org.springframework.data.redis.core.StringRedisTemplate;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.connection.RedisConnection;
import java.util.Set;

/**
 * Provides a mock implementation of StringRedisTemplate for testing.
 *
 * <p>Since RedisAutoConfiguration is disabled in the test profile, we must manually
 * construct a bean that fulfills the dependency injections for components like
 * RedisTokenStorage. This mock uses a nested HashMap to simulate Redis Hash operations.</p>
 */
@Configuration
@Profile("test")
public class TestCacheConfig {

    @SuppressWarnings({ "null", "unchecked" })
    @Bean
    @Primary
    public StringRedisTemplate stringRedisTemplate() {
        StringRedisTemplate template = Mockito.mock(StringRedisTemplate.class);
        ValueOperations<String, String> valueOps = Mockito.mock(ValueOperations.class);
        HashOperations<String, Object, Object> hashOps = Mockito.mock(HashOperations.class);
        
        Map<String, Map<Object, Object>> hashCache = new HashMap<>();
        Map<String, String> valueCache = new HashMap<>();
        Map<String, Set<String>> setCache = new HashMap<>();

        RedisConnection redisConnection = Mockito.mock(RedisConnection.class);
        Mockito.when(redisConnection.getNativeConnection()).thenReturn(null);
        Mockito.doAnswer(invocation -> {
            Object[] commandArgs = invocation.getArguments();
            String command = commandArgs[0].toString();
            if (!"HSCAN".equals(command)) {
                return null;
            }
            byte[] keyBytes = invocation.getArgument(1);
            String key = new String(keyBytes, java.nio.charset.StandardCharsets.UTF_8);
            Map<Object, Object> entries = hashCache.getOrDefault(key, Map.of());
            java.util.List<byte[]> flattened = new java.util.ArrayList<>();
            entries.forEach((field, value) -> {
                flattened.add(field.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                flattened.add(value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            });
            return java.util.List.of("0".getBytes(java.nio.charset.StandardCharsets.UTF_8), flattened);
        }).when(redisConnection).execute(
                Mockito.anyString(), Mockito.any(byte[].class), Mockito.any(byte[].class),
                Mockito.any(byte[].class), Mockito.any(byte[].class));
        Mockito.doAnswer(invocation -> {
            RedisCallback<?> callback = invocation.getArgument(0);
            return callback.doInRedis(redisConnection);
        }).when(template).execute(Mockito.any(RedisCallback.class));
        
        // Mock ValueOperations — set with TTL
        Mockito.doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            String value = invocation.getArgument(1);
            valueCache.put(key, value);
            return null;
        }).when(valueOps).set(Mockito.anyString(), Mockito.anyString(), Mockito.any(Duration.class));
        
        Mockito.doAnswer(invocation -> valueCache.get(invocation.getArgument(0)))
               .when(valueOps).get(Mockito.anyString());

        // Mock ValueOperations — increment (used by AccountLockoutService DT 3.2.23)
        Mockito.doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            String currentStr = valueCache.get(key);
            long newVal = (currentStr == null) ? 1L : Long.parseLong(currentStr) + 1L;
            valueCache.put(key, String.valueOf(newVal));
            return newVal;
        }).when(valueOps).increment(Mockito.anyString());

        // Mock HashOperations
        Mockito.doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            Object hashKey = invocation.getArgument(1);
            Object value = invocation.getArgument(2);
            hashCache.computeIfAbsent(key, k -> new HashMap<>()).put(hashKey, value);
            return null;
        }).when(hashOps).put(Mockito.anyString(), Mockito.any(), Mockito.any());

        Mockito.doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            Object hashKey = invocation.getArgument(1);
            Map<Object, Object> map = hashCache.get(key);
            return map != null ? map.get(hashKey) : null;
        }).when(hashOps).get(Mockito.anyString(), Mockito.any());

        Mockito.doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            Map<Object, Object> map = hashCache.get(key);
            return map != null ? map.keySet() : Set.of();
        }).when(hashOps).keys(Mockito.anyString());

        Mockito.doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            Object hashKey = invocation.getArgument(1);
            Map<Object, Object> map = hashCache.get(key);
            if (map != null) {
                map.remove(hashKey);
            }
            return 1L;
        }).when(hashOps).delete(Mockito.anyString(), Mockito.any());

        // Mock Template — delete
        Mockito.doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            valueCache.remove(key);
            hashCache.remove(key);
            setCache.remove(key);
            return Boolean.TRUE;
        }).when(template).delete(Mockito.anyString());

        // Mock Template — expire (used by AccountLockoutService DT 3.2.23)
        Mockito.when(template.expire(Mockito.anyString(), Mockito.anyLong(), Mockito.any(java.util.concurrent.TimeUnit.class)))
               .thenReturn(Boolean.TRUE);
        Mockito.when(template.expire(Mockito.anyString(), Mockito.any(Duration.class)))
               .thenReturn(Boolean.TRUE);

        Mockito.doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            return valueCache.containsKey(key) || hashCache.containsKey(key) || setCache.containsKey(key);
        }).when(template).hasKey(Mockito.anyString());

        // Mock Template - execute (used by RedisTokenStorage Lua script DT 3.2.4)
        Mockito.doAnswer(invocation -> {
            java.util.List<?> keys = invocation.getArgument(1);
            String key = (String) keys.get(0);
            Object[] args = invocation.getArguments();
            org.springframework.data.redis.core.script.RedisScript<?> script = invocation.getArgument(0);

            if (script.getScriptAsString().contains("current ~= ARGV[2]")) {
                Map<Object, Object> metadata = hashCache.get(key);
                String jti = args[2].toString();
                if (metadata != null && java.util.Objects.equals(metadata.get(jti), args[3])) {
                    metadata.put(jti, args[4]);
                    return 1L;
                }
                return 0L;
            }

            if (keys.size() == 2 && script.getScriptAsString().contains("'NX', 'EX'")) {
                String claimKey = (String) keys.get(1);
                String inputHash = args[2].toString();
                String claimId = args[3].toString();
                if (inputHash.equals(valueCache.get(key)) && !valueCache.containsKey(claimKey)) {
                    valueCache.put(claimKey, claimId);
                    return 1L;
                }
                return 0L;
            }

            if (args.length == 3) {
                if (isRefreshTokenKey(key)) {
                    String familiesKey = (String) keys.get(1);
                    Set<String> families = setCache.remove(familiesKey);
                    if (families != null) {
                        String familyKeyPrefix = args[2].toString();
                        families.forEach(family -> valueCache.remove(familyKeyPrefix + family));
                    }
                    Map<Object, Object> removed = hashCache.remove(key);
                    return removed == null ? 0L : Long.valueOf(removed.size());
                }
                String inputHash = args[2].toString();
                String storedHash = valueCache.get(key);
                if (storedHash != null && storedHash.equals(inputHash)) {
                    valueCache.remove(key);
                    return 1L;
                }
                return 0L;
            }

            String hashKey = args[2].toString();
            String value = args[3].toString();
            hashCache.computeIfAbsent(key, k -> new HashMap<>()).put(hashKey, value);
            return Boolean.TRUE;
        }).when(template).execute(Mockito.any(org.springframework.data.redis.core.script.RedisScript.class), Mockito.anyList(), Mockito.any(), Mockito.any(), Mockito.any());

        Mockito.doAnswer(invocation -> {
            java.util.List<?> keys = invocation.getArgument(1);
            String tokenKey = (String) keys.get(0);
            String familyKey = (String) keys.get(1);
            String familiesKey = (String) keys.get(2);
            String jti = invocation.getArgument(2).toString();
            String value = invocation.getArgument(3).toString();
            String familyId = invocation.getArgument(5).toString();
            hashCache.computeIfAbsent(tokenKey, k -> new HashMap<>()).put(jti, value);
            valueCache.put(familyKey, jti);
            setCache.computeIfAbsent(familiesKey, ignored -> new java.util.HashSet<>()).add(familyId);
            hashCache.computeIfAbsent((String) keys.get(3), k -> new HashMap<>())
                    .put(jti, invocation.getArgument(6).toString());
            hashCache.computeIfAbsent((String) keys.get(4), k -> new HashMap<>())
                    .put(invocation.getArgument(7).toString(), jti);
            return Boolean.TRUE;
        }).when(template).execute(Mockito.any(org.springframework.data.redis.core.script.RedisScript.class), Mockito.anyList(),
                Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any(), Mockito.any());

        Mockito.doAnswer(invocation -> {
            java.util.List<?> keys = invocation.getArgument(1);
            String key = (String) keys.get(0);
            String familyKey = (String) keys.get(1);
            String familiesKey = (String) keys.get(2);
            String currentJti = invocation.getArgument(2).toString();
            String currentHash = invocation.getArgument(3).toString();
            String nextJti = invocation.getArgument(4).toString();
            String nextHash = invocation.getArgument(5).toString();
            String currentFamilyId = invocation.getArgument(7).toString();
            Map<Object, Object> sessions = hashCache.get(key);

            if (sessions == null) {
                return 0L;
            }

            Object storedValObj = sessions.get(currentJti);
            if (storedValObj != null) {
                String storedVal = storedValObj.toString();
                String storedHash = storedVal;
                String storedFamily = "unknown-family";
                int colonIdx = storedVal.indexOf(':');
                if (colonIdx != -1) {
                    storedHash = storedVal.substring(0, colonIdx);
                    storedFamily = storedVal.substring(colonIdx + 1);
                }

                if (currentHash.equals(storedHash)) {
                    sessions.remove(currentJti);
                    sessions.put(nextJti, nextHash + ":" + storedFamily);
                    Map<Object, Object> metadata = hashCache.get((String) keys.get(3));
                    if (metadata != null) {
                        Object serialized = metadata.remove(currentJti);
                        if (serialized != null) {
                            String value = serialized.toString();
                            String[] parts = value.split("\\|", -1);
                            parts[2] = invocation.getArgument(8).toString();
                            parts[3] = invocation.getArgument(9).toString();
                            String updated = String.join("|", parts);
                            metadata.put(nextJti, updated);
                            hashCache.computeIfAbsent((String) keys.get(4), ignored -> new HashMap<>())
                                    .put(parts[0], nextJti);
                        }
                    }
                    valueCache.put(familyKey, nextJti);
                    setCache.computeIfAbsent(familiesKey, ignored -> new java.util.HashSet<>()).add(storedFamily);
                    return 1L;
                }
            }

            // Reuse detection: if the old token is replayed, revoke the remaining token family.
            boolean reuseDetected = false;
            for (Map.Entry<Object, Object> entry : sessions.entrySet()) {
                String val = entry.getValue().toString();
                int colonIdx = val.indexOf(':');
                if (colonIdx != -1) {
                    String storedFamily = val.substring(colonIdx + 1);
                    if (storedFamily.equals(currentFamilyId)) {
                        reuseDetected = true;
                        break;
                    }
                }
            }

            if (reuseDetected) {
                // Revoke all keys belonging to this family!
                java.util.List<Object> keysToRemove = new java.util.ArrayList<>();
                for (Map.Entry<Object, Object> entry : sessions.entrySet()) {
                    String val = entry.getValue().toString();
                    int colonIdx = val.indexOf(':');
                    if (colonIdx != -1) {
                        String storedFamily = val.substring(colonIdx + 1);
                        if (storedFamily.equals(currentFamilyId)) {
                            keysToRemove.add(entry.getKey());
                        }
                    }
                }
                for (Object k : keysToRemove) {
                    sessions.remove(k);
                }
                valueCache.remove(familyKey);
                Set<String> families = setCache.get(familiesKey);
                if (families != null) {
                    families.remove(currentFamilyId);
                }
                return -1L; // Compromised!
            }

            return 0L;
        }).when(template).execute(
                Mockito.any(org.springframework.data.redis.core.script.RedisScript.class),
                Mockito.anyList(),
                Mockito.any(),
                Mockito.any(),
                Mockito.any(),
                Mockito.any(),
                Mockito.any(),
                Mockito.any(),
                Mockito.any(),
                Mockito.any()
        );

        Mockito.doAnswer(invocation -> {
            java.util.List<?> keys = invocation.getArgument(1);
            String key = (String) keys.get(0);
            org.springframework.data.redis.core.script.RedisScript<?> script = invocation.getArgument(0);
            if (keys.size() == 2 && script.getScriptAsString().contains("redis.call('GET', KEYS[2])")) {
                String claimKey = (String) keys.get(1);
                String claimId = invocation.getArgument(2).toString();
                if (claimId.equals(valueCache.get(claimKey))) {
                    valueCache.remove(key);
                    valueCache.remove(claimKey);
                    return 1L;
                }
                return 0L;
            }
            if (key.startsWith("recovery:claim:")
                    && script.getScriptAsString().contains("redis.call('DEL', KEYS[1])")) {
                String claimId = invocation.getArgument(2).toString();
                if (claimId.equals(valueCache.get(key))) {
                    valueCache.remove(key);
                    return 1L;
                }
                return 0L;
            }
            if (isRefreshTokenKey(key)) {
                Set<String> families = setCache.remove((String) keys.get(1));
                if (families != null) {
                    String familyKeyPrefix = invocation.getArgument(2).toString();
                    families.forEach(family -> valueCache.remove(familyKeyPrefix + family));
                }
                Map<Object, Object> removed = hashCache.remove(key);
                if (keys.size() > 2) {
                    hashCache.remove((String) keys.get(2));
                    hashCache.remove((String) keys.get(3));
                }
                return removed == null ? 0L : Long.valueOf(removed.size());
            }
            String inputHash = invocation.getArgument(2).toString();
            String storedHash = valueCache.get(key);
            if (storedHash != null && storedHash.equals(inputHash)) {
                valueCache.remove(key);
                return 1L;
            }
            return 0L;
        }).when(template).execute(Mockito.any(org.springframework.data.redis.core.script.RedisScript.class), Mockito.anyList(), Mockito.any());

        Mockito.doAnswer(invocation -> {
            java.util.List<?> keys = invocation.getArgument(1);
            String key = (String) keys.get(0);
            if (isRefreshTokenKey(key)) {
                org.springframework.data.redis.core.script.RedisScript<?> script = invocation.getArgument(0);
                String requestedId = invocation.getArgument(2).toString();
                String familyKeyPrefix = invocation.getArgument(3).toString();
                Map<Object, Object> sessions = hashCache.get(key);
                if (sessions == null) {
                    return 0L;
                }
                if (script.getScriptAsString().contains("fields[i] ~= ARGV[1]")) {
                    java.util.List<Object> removed = new java.util.ArrayList<>();
                    sessions.keySet().forEach(existingJti -> {
                        if (!existingJti.equals(requestedId)) {
                            removed.add(existingJti);
                        }
                    });
                    removed.forEach(existingJti -> removeRefreshSession(
                            sessions,
                            (String) keys.get(1),
                            familyKeyPrefix,
                            existingJti,
                            valueCache,
                            setCache));
                    if (keys.size() > 3) {
                        Map<Object, Object> metadata = hashCache.get((String) keys.get(2));
                        Map<Object, Object> publicIndex = hashCache.get((String) keys.get(3));
                        removed.forEach(existingJti -> removeSessionMetadata(metadata, publicIndex, existingJti));
                    }
                    return Long.valueOf(removed.size());
                }
                String jti = requestedId;
                if (script.getScriptAsString().contains("HGET', KEYS[4]")) {
                    Map<Object, Object> publicIndex = hashCache.get((String) keys.get(3));
                    Object resolved = publicIndex == null ? null : publicIndex.get(requestedId);
                    if (resolved == null) {
                        return 0L;
                    }
                    jti = resolved.toString();
                    removeSessionMetadata(hashCache.get((String) keys.get(2)), publicIndex, jti);
                } else if (keys.size() > 3) {
                    removeSessionMetadata(hashCache.get((String) keys.get(2)),
                            hashCache.get((String) keys.get(3)), jti);
                }
                return removeRefreshSession(
                        sessions,
                        (String) keys.get(1),
                        familyKeyPrefix,
                        jti,
                        valueCache,
                        setCache);
            }
            return 0L;
        }).when(template).execute(Mockito.any(org.springframework.data.redis.core.script.RedisScript.class), Mockito.anyList(), Mockito.any(), Mockito.any());
        
        Mockito.when(template.opsForValue()).thenReturn(valueOps);
        Mockito.when(template.opsForHash()).thenReturn(hashOps);
        return template;
    }

    private static boolean isRefreshTokenKey(String key) {
        return key.startsWith("refresh:{") && key.endsWith("}:tokens");
    }

    private static long removeRefreshSession(Map<Object, Object> sessions,
                                             String familiesKey,
                                             String familyKeyPrefix,
                                             Object jti,
                                             Map<String, String> valueCache,
                                             Map<String, Set<String>> setCache) {
        Object stored = sessions.remove(jti);
        if (stored == null) {
            return 0L;
        }
        String storedValue = stored.toString();
        int colonIdx = storedValue.indexOf(':');
        if (colonIdx != -1) {
            String family = storedValue.substring(colonIdx + 1);
            valueCache.remove(familyKeyPrefix + family);
            Set<String> families = setCache.get(familiesKey);
            if (families != null) {
                families.remove(family);
            }
        }
        if (sessions.isEmpty()) {
            setCache.remove(familiesKey);
        }
        return 1L;
    }

    private static void removeSessionMetadata(Map<Object, Object> metadata,
                                              Map<Object, Object> publicIndex,
                                              Object jti) {
        if (metadata == null) {
            return;
        }
        Object serialized = metadata.remove(jti);
        if (serialized != null && publicIndex != null) {
            String publicId = serialized.toString().split("\\|", 2)[0];
            publicIndex.remove(publicId);
        }
    }
}
