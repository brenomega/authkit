package io.github.brenomega.authkit.infrastructure.cache;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.List;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.service.spi.TokenStorage;

/**
 * Implementation of TokenStorage utilizing Spring Data Redis.
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
        // DT 3.2.4: Hashing refresh tokens prior to storage for cache compromise mitigation
        String hashedToken = hashToken(rawToken);
        String key = PREFIX + userId;
        long durationSeconds = Duration.ofDays(durationDays).getSeconds();
        
        // Use Lua script to ensure atomicity of HSET and EXPIRE
        String luaScript = 
            "redis.call('HSET', KEYS[1], ARGV[1], ARGV[2]); " +
            "redis.call('EXPIRE', KEYS[1], ARGV[3]); " +
            "return true;";
            
        org.springframework.data.redis.core.script.DefaultRedisScript<Boolean> script = 
            new org.springframework.data.redis.core.script.DefaultRedisScript<>(luaScript, Boolean.class);
            
        redisTemplate.execute(script, List.of(key), jti, hashedToken, String.valueOf(durationSeconds));
    }

    @SuppressWarnings("null")
    @Override
    public boolean validateToken(String userId, String jti, String rawToken) {
        String key = PREFIX + userId;
        Object storedHashObj = redisTemplate.opsForHash().get(key, jti);

        if (storedHashObj == null) {
            return false;
        }

        String storedHash = (String) storedHashObj;
        String inputHash = hashToken(rawToken);

        // DT 3.2.13: Preventing Side-Channel Timing Attacks using constant-time comparison
        return MessageDigest.isEqual(
                storedHash.getBytes(StandardCharsets.UTF_8),
                inputHash.getBytes(StandardCharsets.UTF_8)
        );
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

    @Override
    public void revokeOtherSessions(String userId, String currentJti) {
        String key = PREFIX + userId;
        java.util.Set<Object> keys = redisTemplate.opsForHash().keys(key);
        for (Object jti : keys) {
            if (!jti.equals(currentJti)) {
                redisTemplate.opsForHash().delete(key, jti);
            }
        }
    }

    @SuppressWarnings("null")
    @Override
    public void storeRecoveryToken(String email, String rawToken, long durationMinutes) {
        // DT 3.2.4: Hashing tokens prior to storage
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
        // DT 3.2.13: Constant-time verification
        return MessageDigest.isEqual(
                storedHash.getBytes(StandardCharsets.UTF_8),
                inputHash.getBytes(StandardCharsets.UTF_8)
        );
    }

    @Override
    public void revokeRecoveryToken(String email) {
        String key = "recovery:token:" + email;
        redisTemplate.delete(key);
    }

    private String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Required cryptographic algorithm not found", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
