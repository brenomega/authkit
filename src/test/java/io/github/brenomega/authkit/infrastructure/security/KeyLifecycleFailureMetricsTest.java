package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.junit.jupiter.api.Test;
import org.aspectj.lang.ProceedingJoinPoint;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class KeyLifecycleFailureMetricsTest {
    @Test
    void failureFamiliesRemainFailClosedAndDoNotExposeExceptionContentInTags() throws Throwable {
        var meters = new SimpleMeterRegistry();
        var metrics = new KeyLifecycleFailureMetrics(meters);
        var failure = new IllegalStateException("test-secret-must-not-be-a-tag");
        var call = mock(ProceedingJoinPoint.class);
        when(call.proceed()).thenThrow(failure);
        assertSame(failure, assertThrows(IllegalStateException.class, () -> metrics.jwks(call)));
        assertSame(failure, assertThrows(IllegalStateException.class, () -> metrics.mfa(call)));
        var encoder = metrics.signingEncoder(parameters -> { throw failure; });
        assertSame(failure, assertThrows(IllegalStateException.class, () -> encoder.encode(null)));
        for (String family : java.util.List.of("jwks", "mfa", "signing")) {
            assertEquals(1, meters.get("security.key.lifecycle.failure").tag("family", family).counter().count());
        }
        assertFalse(meters.getMeters().toString().contains(failure.getMessage()));
    }
}
