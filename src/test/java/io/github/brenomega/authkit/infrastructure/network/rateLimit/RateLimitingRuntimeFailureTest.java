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

import io.github.bucket4j.BucketConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.distributed.proxy.RemoteBucketBuilder;

public class RateLimitingRuntimeFailureTest {

    @Test
    @DisplayName("Fail-Open: Runtime Redis exception during tryConsume degrades to Layer 1 cleanly")
    void runtimeRedisFailure_degradesToLayer1() throws Exception {

        NetworkIpResolver ipResolver = mock(NetworkIpResolver.class);
        when(ipResolver.resolveClientIp(any())).thenReturn("10.0.0.1");

        RateLimitingProperties properties = new RateLimitingProperties();
        properties.setLocalCapacity(10);
        properties.setGlobalCapacity(10);
        properties.setLocalMaxSize(100);

        io.micrometer.core.instrument.MeterRegistry meterRegistry = mock(
            io.micrometer.core.instrument.MeterRegistry.class,
            org.mockito.Mockito.RETURNS_DEEP_STUBS);
        RateLimitingFilter filter = new RateLimitingFilter(ipResolver, properties, Optional.empty(), meterRegistry);

        @SuppressWarnings("unchecked")
        ProxyManager<byte[]> proxyManager = mock(ProxyManager.class);
        @SuppressWarnings("unchecked")
        RemoteBucketBuilder<byte[]> bucketBuilder = mock(RemoteBucketBuilder.class);
        io.github.bucket4j.distributed.BucketProxy bucket = mock(io.github.bucket4j.distributed.BucketProxy.class);

        when(proxyManager.builder()).thenReturn(bucketBuilder);
        when(bucketBuilder.build(any(byte[].class),
                org.mockito.ArgumentMatchers.<Supplier<BucketConfiguration>>any())).thenReturn(bucket);
        when(bucket.tryConsume(1)).thenThrow(new RuntimeException("Simulated Redis Command Timeout"));

        Field proxyManagerField = RateLimitingFilter.class.getDeclaredField("proxyManager");
        proxyManagerField.setAccessible(true);
        proxyManagerField.set(filter, proxyManager);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/api/v1/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        filter.doFilter(request, response, filterChain);

        assertEquals(200, response.getStatus(), "Expected 200 OK due to Fail-Open degradation");
    }
}
