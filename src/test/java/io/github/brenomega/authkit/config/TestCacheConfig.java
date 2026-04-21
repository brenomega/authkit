package io.github.brenomega.authkit.config;

import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Provides a mock implementation of StringRedisTemplate for testing.
 *
 * <p>Since RedisAutoConfiguration is disabled in the test profile, we must manually
 * construct a bean that fulfills the dependency injections for components like
 * RedisTokenStorage. This mock uses a basic HashMap to simulate cache retention.</p>
 */
@Configuration
public class TestCacheConfig {

    @Bean
    @Primary
    public StringRedisTemplate stringRedisTemplate() {
        StringRedisTemplate template = Mockito.mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> ops = Mockito.mock(ValueOperations.class);
        
        Map<String, String> cache = new HashMap<>();
        
        Mockito.doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            String value = invocation.getArgument(1);
            cache.put(key, value);
            return null;
        }).when(ops).set(Mockito.anyString(), Mockito.anyString(), Mockito.any(Duration.class));
        
        Mockito.doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            return cache.get(key);
        }).when(ops).get(Mockito.anyString());
        
        Mockito.doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            cache.remove(key);
            return Boolean.TRUE;
        }).when(template).delete(Mockito.anyString());
        
        Mockito.when(template.opsForValue()).thenReturn(ops);
        return template;
    }
}
