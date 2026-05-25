package io.github.brenomega.authkit.infrastructure.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.github.brenomega.authkit.infrastructure.network.ip.NetworkIpResolver;

class SecurityEventServiceTest {

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    @DisplayName("Security events persist privacy-safe identifiers and metrics")
    void recordForEmail_persistsPrivacySafeIdentifiers() {
        SecurityEventRepository repository = mock(SecurityEventRepository.class);
        NetworkIpResolver ipResolver = mock(NetworkIpResolver.class);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        SecurityEventService service = new SecurityEventService(
                repository,
                ipResolver,
                meterRegistry,
                new ObjectMapper());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.addHeader("User-Agent", "JUnit Browser");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        when(ipResolver.resolveClientIp(any())).thenReturn("203.0.113.25");

        service.recordForEmail(
                SecurityEventType.LOGIN_FAILURE,
                SecurityEventOutcome.FAILURE,
                SecurityEventSeverity.MEDIUM,
                "User@Example.COM",
                "invalid_credentials");

        ArgumentCaptor<SecurityEvent> eventCaptor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(repository).save(eventCaptor.capture());

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
        assertEquals(1.0, meterRegistry.counter("security.login.failed").count());
    }
}
