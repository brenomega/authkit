package io.github.brenomega.authkit.infrastructure.network.rateLimit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.brenomega.authkit.infrastructure.network.config.RateLimitingProperties;
import io.github.brenomega.authkit.infrastructure.network.ip.NetworkIpResolver;
import java.lang.reflect.Field;
import java.util.Optional;
import java.util.function.Supplier;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.distributed.proxy.RemoteBucketBuilder;

public class RateLimitingRuntimeFailureTest {

    @SuppressWarnings("unchecked")
    @Test
    @DisplayName("Fail-Open: Runtime Redis exception during tryConsume degrades to Layer 1 cleanly")
    void runtimeRedisFailure_degradesToLayer1() throws Exception {
        // 1. Mock IP Resolver
        NetworkIpResolver ipResolver = mock(NetworkIpResolver.class);
        when(ipResolver.resolveClientIp(any())).thenReturn("10.0.0.1");

        // 2. Setup Properties
        RateLimitingProperties properties = new RateLimitingProperties();
        properties.setLocalCapacity(10);
        properties.setGlobalCapacity(10);
        properties.setLocalMaxSize(100);

        // 3. Create Filter (with Optional.empty() to initialize cleanly)
        io.micrometer.core.instrument.MeterRegistry meterRegistry = mock(io.micrometer.core.instrument.MeterRegistry.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        RateLimitingFilter filter = new RateLimitingFilter(ipResolver, properties, Optional.empty(), meterRegistry);

        // 4. Mock ProxyManager and Bucket to throw exception on tryConsume
        ProxyManager<byte[]> proxyManager = mock(ProxyManager.class);
        RemoteBucketBuilder<byte[]> bucketBuilder = mock(RemoteBucketBuilder.class);
        io.github.bucket4j.distributed.BucketProxy bucket = mock(io.github.bucket4j.distributed.BucketProxy.class);

        when(proxyManager.builder()).thenReturn(bucketBuilder);
        when(bucketBuilder.build(any(byte[].class), any(Supplier.class))).thenReturn(bucket);
        when(bucket.tryConsume(1)).thenThrow(new RuntimeException("Simulated Redis Command Timeout"));

        // Inject the mocked ProxyManager via reflection
        Field proxyManagerField = RateLimitingFilter.class.getDeclaredField("proxyManager");
        proxyManagerField.setAccessible(true);
        proxyManagerField.set(filter, proxyManager);

        // 5. Execute Filter
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/v1/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        filter.doFilter(request, response, filterChain);

        // 6. Verify fail-open behavior
        // Since Layer 1 (Caffeine) has capacity, it allows the request.
        // Layer 2 (Redis) throws RuntimeException, which should be caught, logged, and allow the request to proceed.
        // Status should be 200 OK, meaning no 500 Internal Server Error leaked out.
        assertEquals(200, response.getStatus(), "Expected 200 OK due to Fail-Open degradation");
    }
}
