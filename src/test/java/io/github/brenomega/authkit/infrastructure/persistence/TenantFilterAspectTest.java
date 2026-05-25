package io.github.brenomega.authkit.infrastructure.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import org.aspectj.lang.ProceedingJoinPoint;
import org.hibernate.Filter;
import org.hibernate.Session;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import jakarta.persistence.EntityManager;

class TenantFilterAspectTest {

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Enables and disables tenant filter around authenticated service calls")
    void enforceTenantFilter_validTenantClaim_enablesAndDisablesFilter() throws Throwable {
        EntityManager entityManager = mock(EntityManager.class);
        Session session = mock(Session.class);
        Filter filter = mock(Filter.class);
        ProceedingJoinPoint joinPoint = mock(ProceedingJoinPoint.class);
        String tenantId = UUID.randomUUID().toString();

        when(entityManager.unwrap(Session.class)).thenReturn(session);
        when(session.enableFilter("tenantFilter")).thenReturn(filter);
        when(filter.setParameter("tenantId", tenantId)).thenReturn(filter);
        when(joinPoint.proceed()).thenReturn("done");
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(Map.of("tenant_id", tenantId))));

        Object result = new TenantFilterAspect(entityManager).enforceTenantFilter(joinPoint);

        assertEquals("done", result);
        verify(session).enableFilter("tenantFilter");
        verify(filter).setParameter("tenantId", tenantId);
        verify(session).disableFilter("tenantFilter");
    }

    @SuppressWarnings("null")
    @Test
    @DisplayName("Ignores malformed tenant claims without blocking the service call")
    void enforceTenantFilter_invalidTenantClaim_doesNotEnableFilter() throws Throwable {
        EntityManager entityManager = mock(EntityManager.class);
        ProceedingJoinPoint joinPoint = mock(ProceedingJoinPoint.class);

        when(joinPoint.proceed()).thenReturn("done");
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt(Map.of("tenant_id", "not-a-uuid"))));

        Object result = new TenantFilterAspect(entityManager).enforceTenantFilter(joinPoint);

        assertEquals("done", result);
        verify(entityManager, never()).unwrap(Session.class);
    }

    private Jwt jwt(Map<String, Object> claims) {
        Instant now = Instant.now();
        java.util.HashMap<String, Object> allClaims = new java.util.HashMap<>(claims);
        allClaims.put("sub", UUID.randomUUID().toString());
        return new Jwt(
                "token",
                now,
                now.plusSeconds(300),
                Map.of("alg", "RS256"),
                allClaims);
    }
}
