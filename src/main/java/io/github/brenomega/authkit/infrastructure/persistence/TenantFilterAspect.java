package io.github.brenomega.authkit.infrastructure.persistence;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.hibernate.Session;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

/**
 * Aspect handling Multi-Tenancy boundary enforcement at the persistance layer (DT 3.5.1).
 *
 * <p>Intercepts service calls to enforce the global Hibernate tenantFilter whenever
 * the current security context contains a valid tenantId.</p>
 */
@Aspect
@Component
public class TenantFilterAspect {

    @PersistenceContext
    private EntityManager entityManager;

    @Before("execution(* io.github.brenomega.authkit.service..*(..))")
    public void enableTenantFilter(JoinPoint joinPoint) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            String tenantId = jwt.getClaimAsString("tenantId");
            if (tenantId != null) {
                // We unwrap the raw Hibernate Session to inject the filter parameter
                Session session = entityManager.unwrap(Session.class);
                session.enableFilter("tenantFilter").setParameter("tenantId", tenantId);
            }
        }
    }
}
