package io.github.brenomega.authkit.infrastructure.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.github.brenomega.authkit.infrastructure.security.AuthProperties;
import io.github.brenomega.authkit.infrastructure.network.ip.NetworkIpResolver;

class SecurityEventServiceTest {

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("Security events persist privacy-safe identifiers and metrics")
    void recordForEmail_persistsPrivacySafeIdentifiers() throws Exception {
        SecurityEventWriter writer = mock(SecurityEventWriter.class);
        NetworkIpResolver ipResolver = mock(NetworkIpResolver.class);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        AuthProperties authProperties = new AuthProperties();
        authProperties.getAudit().setAsyncEnabled(false);
        authProperties.getAudit().setHashPepper("unit-test-audit-hash-pepper-at-least-32-chars");
        ObjectMapper objectMapper = new ObjectMapper();
        AuditDigestService auditDigestService = new AuditDigestService(authProperties);
        SecurityEventService service = new SecurityEventService(
                writer,
                mock(ThreadPoolTaskExecutor.class),
                ipResolver,
                meterRegistry,
                objectMapper,
                authProperties,
                auditDigestService);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.addHeader("User-Agent", "JUnit Browser");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        when(ipResolver.resolveClientIp(any())).thenReturn("203.0.113.25");

        service.recordForEmail(
                SecurityEventType.LOGIN_FAILURE,
                SecurityEventOutcome.FAILURE,
                SecurityEventSeverity.MEDIUM,
                "User@Example.COM",
                "invalid_credentials",
                java.util.Map.of("resetToken", "secret-token", "policy", "login"));

        ArgumentCaptor<SecurityEvent> eventCaptor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(writer).persist(eventCaptor.capture());

        SecurityEvent event = eventCaptor.getValue();
        assertEquals(SecurityEventType.LOGIN_FAILURE, event.getEventType());
        assertEquals("u***@example.com", event.getEmailMasked());
        assertNotNull(event.getEmailHash());
        assertFalse(event.getEmailHash().contains("example.com"));
        assertNotNull(event.getClientIpHash());
        assertFalse(event.getClientIpHash().contains("203.0.113.25"));
        assertNotNull(event.getUserAgentHash());
        assertEquals("POST", event.getRequestMethod());
        assertEquals("/api/v1/auth/login", event.getRequestPath());
        assertNotNull(event.getEventHash());
        assertEquals("[REDACTED]", objectMapper.readTree(event.getMetadataJson()).get("resetToken").asText());
        assertEquals("login", objectMapper.readTree(event.getMetadataJson()).get("policy").asText());
        assertEquals(1.0, meterRegistry.counter("security.login.failed").count());
    }

    @Test
    @DisplayName("Security events persist synchronously when the async writer is saturated")
    void recordForEmail_writerSaturated_persistsSynchronously() {
        SecurityEventWriter writer = mock(SecurityEventWriter.class);
        ThreadPoolTaskExecutor executor = mock(ThreadPoolTaskExecutor.class);
        NetworkIpResolver ipResolver = mock(NetworkIpResolver.class);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        AuthProperties authProperties = new AuthProperties();
        authProperties.getAudit().setAsyncEnabled(true);
        authProperties.getAudit().setPersistSynchronouslyOnOverload(true);
        authProperties.getAudit().setHashPepper("unit-test-audit-hash-pepper-at-least-32-chars");
        AuditDigestService auditDigestService = new AuditDigestService(authProperties);
        SecurityEventService service = new SecurityEventService(
                writer,
                executor,
                ipResolver,
                meterRegistry,
                new ObjectMapper(),
                authProperties,
                auditDigestService);

        doThrow(new TaskRejectedException("queue full")).when(executor).execute(any(Runnable.class));

        service.recordForEmail(
                SecurityEventType.PASSWORD_RESET_REQUESTED,
                SecurityEventOutcome.INFO,
                SecurityEventSeverity.MEDIUM,
                "user@example.com",
                "password_reset_requested");

        verify(writer).persist(any(SecurityEvent.class));
        assertEquals(1.0, meterRegistry.counter(
                "security.events.overloaded",
                "type", SecurityEventType.PASSWORD_RESET_REQUESTED.name(),
                "severity", SecurityEventSeverity.MEDIUM.name()).count());
        assertEquals(1.0, meterRegistry.counter(
                "security.events.fallback.persisted",
                "type", SecurityEventType.PASSWORD_RESET_REQUESTED.name(),
                "severity", SecurityEventSeverity.MEDIUM.name()).count());
    }

    @Test
    @DisplayName("MFA security events increment alertable specific metrics")
    void recordForEmail_mfaFailureRecordsSpecificMetric() {
        SecurityEventWriter writer = mock(SecurityEventWriter.class);
        NetworkIpResolver ipResolver = mock(NetworkIpResolver.class);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        AuthProperties authProperties = new AuthProperties();
        authProperties.getAudit().setAsyncEnabled(false);
        authProperties.getAudit().setHashPepper("unit-test-audit-hash-pepper-at-least-32-chars");
        SecurityEventService service = new SecurityEventService(
                writer,
                mock(ThreadPoolTaskExecutor.class),
                ipResolver,
                meterRegistry,
                new ObjectMapper(),
                authProperties,
                new AuditDigestService(authProperties));

        service.recordForEmail(
                SecurityEventType.MFA_CHALLENGE_FAILED,
                SecurityEventOutcome.DENIED,
                SecurityEventSeverity.HIGH,
                "mfa@example.com",
                "login_mfa_invalid_code");

        assertEquals(1.0, meterRegistry.counter("security.mfa.challenge.failed").count());
        assertEquals(1.0, meterRegistry.counter("security.mfa.login.failed").count());
        assertEquals(0.0, meterRegistry.counter("security.mfa.step_up.failed").count());
    }

    @Test
    @DisplayName("MFA step-up failures increment a distinct low-cardinality metric")
    void recordForEmail_mfaStepUpFailureRecordsDistinctMetric() {
        SecurityEventWriter writer = mock(SecurityEventWriter.class);
        NetworkIpResolver ipResolver = mock(NetworkIpResolver.class);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        AuthProperties authProperties = new AuthProperties();
        authProperties.getAudit().setAsyncEnabled(false);
        authProperties.getAudit().setHashPepper("unit-test-audit-hash-pepper-at-least-32-chars");
        SecurityEventService service = new SecurityEventService(
                writer,
                mock(ThreadPoolTaskExecutor.class),
                ipResolver,
                meterRegistry,
                new ObjectMapper(),
                authProperties,
                new AuditDigestService(authProperties));

        service.recordForEmail(
                SecurityEventType.MFA_CHALLENGE_FAILED,
                SecurityEventOutcome.DENIED,
                SecurityEventSeverity.HIGH,
                "mfa@example.com",
                "password_change_mfa_invalid");

        assertEquals(1.0, meterRegistry.counter("security.mfa.challenge.failed").count());
        assertEquals(0.0, meterRegistry.counter("security.mfa.login.failed").count());
        assertEquals(1.0, meterRegistry.counter("security.mfa.step_up.failed").count());
    }
}
