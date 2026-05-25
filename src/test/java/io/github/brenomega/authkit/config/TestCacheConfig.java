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
            return Boolean.TRUE;
        }).when(template).delete(Mockito.anyString());

        // Mock Template — expire (used by AccountLockoutService DT 3.2.23)
        Mockito.when(template.expire(Mockito.anyString(), Mockito.anyLong(), Mockito.any(java.util.concurrent.TimeUnit.class)))
               .thenReturn(Boolean.TRUE);

        // Mock Template - execute (used by RedisTokenStorage Lua script DT 3.2.4)
        Mockito.doAnswer(invocation -> {
            java.util.List<?> keys = invocation.getArgument(1);
            String key = (String) keys.get(0);
            Object[] args = invocation.getArguments();

            if (args.length == 3) {
                if (key.startsWith("refresh:token:")) {
                    String currentJti = args[2].toString();
                    Map<Object, Object> sessions = hashCache.get(key);
                    if (sessions != null) {
                        sessions.keySet().removeIf(jti -> !jti.equals(currentJti));
                        return Long.valueOf(sessions.size());
                    }
                    return 0L;
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
            String key = (String) keys.get(0);
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
                Mockito.any()
        );

        Mockito.doAnswer(invocation -> {
            java.util.List<?> keys = invocation.getArgument(1);
            String key = (String) keys.get(0);
            if (key.startsWith("refresh:token:")) {
                String currentJti = invocation.getArgument(2).toString();
                Map<Object, Object> sessions = hashCache.get(key);
                if (sessions != null) {
                    sessions.keySet().removeIf(jti -> !jti.equals(currentJti));
                    return Long.valueOf(sessions.size());
                }
                return 0L;
            }
            String inputHash = invocation.getArgument(2).toString();
            String storedHash = valueCache.get(key);
            if (storedHash != null && storedHash.equals(inputHash)) {
                valueCache.remove(key);
                return 1L;
            }
            return 0L;
        }).when(template).execute(Mockito.any(org.springframework.data.redis.core.script.RedisScript.class), Mockito.anyList(), Mockito.any());
        
        Mockito.when(template.opsForValue()).thenReturn(valueOps);
        Mockito.when(template.opsForHash()).thenReturn(hashOps);
        return template;
    }
}
