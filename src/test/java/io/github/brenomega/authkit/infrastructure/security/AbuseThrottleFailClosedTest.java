package io.github.brenomega.authkit.infrastructure.security;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Optional;
import java.time.Duration;

import org.junit.jupiter.api.Test;

import io.github.brenomega.authkit.exception.AbuseProtectionUnavailableException;
import io.github.brenomega.authkit.infrastructure.audit.AuditDigestService;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

class AbuseThrottleFailClosedTest {

    @Test
    void startupRedisLossHonorsEnabledAndDisabledPolicy() {
        AuthProperties strict = properties(true);
        SimpleMeterRegistry meters = new SimpleMeterRegistry();
        AbuseThrottleService strictService = new AbuseThrottleService(
                Optional.empty(), new AuditDigestService(strict), meters, strict);
        assertThrows(AbuseProtectionUnavailableException.class,
                () -> strictService.check(AbuseRateLimitPolicy.LOGIN_ENDPOINT_IP, "203.0.113.1"));
        assertEquals(1.0, meters.find("security.abuse_control.fail_closed").counter().count());
        assertDoesNotThrow(() -> strictService.check(AbuseRateLimitPolicy.SESSION_LIST_USER, "user"));

        AuthProperties available = properties(false);
        AbuseThrottleService fallbackService = new AbuseThrottleService(
                Optional.empty(), new AuditDigestService(available), new SimpleMeterRegistry(), available);
        assertDoesNotThrow(() -> fallbackService.check(AbuseRateLimitPolicy.LOGIN_ENDPOINT_IP, "203.0.113.2"));
    }

    @Test
    void runtimeRedisLossFailsClosedOnlyWhenEnabled() {
        RedisURI unreachable = RedisURI.builder()
                .withHost("127.0.0.1")
                .withPort(1)
                .withTimeout(Duration.ofMillis(100))
                .build();
        RedisClient redisClient = RedisClient.create(unreachable);
        try {
            SimpleMeterRegistry meters = new SimpleMeterRegistry();
            AuthProperties strict = properties(true);
            AbuseThrottleService service = new AbuseThrottleService(
                    Optional.of(redisClient), new AuditDigestService(strict), meters, strict);

            assertThrows(AbuseProtectionUnavailableException.class,
                    () -> service.check(AbuseRateLimitPolicy.OAUTH_TOKEN_IP, "203.0.113.3"));
            assertEquals(1.0, meters.find("security.abuse_control.fail_closed").counter().count());
        } finally {
            redisClient.shutdown();
        }
    }

    private AuthProperties properties(boolean failClosed) {
        AuthProperties properties = new AuthProperties();
        properties.getAudit().setHashPepper("unit-test-audit-hash-pepper-at-least-32-characters");
        properties.getAbuseControl().setFailClosedHighRisk(failClosed);
        return properties;
    }
}
