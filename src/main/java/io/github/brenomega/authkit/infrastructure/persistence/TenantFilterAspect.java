package io.github.brenomega.authkit.infrastructure.persistence;

import java.util.UUID;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.hibernate.Session;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import io.github.brenomega.authkit.domain.user.util.JwtTenantResolver;
import jakarta.persistence.EntityManager;

@Aspect
@Component
public class TenantFilterAspect {

    private static final String FILTER_NAME = "tenantFilter";
    private static final ThreadLocal<Integer> FILTER_DEPTH = ThreadLocal.withInitial(() -> 0);

    private final EntityManager entityManager;

    public TenantFilterAspect(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Around("execution(* io.github.brenomega.authkit.service..*(..))")
    public Object enforceTenantFilter(ProceedingJoinPoint joinPoint) throws Throwable {
        String tenantId = currentTenantId();
        int depth = FILTER_DEPTH.get();
        boolean enabledHere = tenantId != null && depth == 0;

        if (enabledHere) {
            Session session = entityManager.unwrap(Session.class);
            session.enableFilter(FILTER_NAME).setParameter("tenantId", tenantId);
        }

        FILTER_DEPTH.set(depth + 1);
        try {
            return joinPoint.proceed();
        } finally {
            int nextDepth = FILTER_DEPTH.get() - 1;
            if (nextDepth <= 0) {
                if (enabledHere) {
                    entityManager.unwrap(Session.class).disableFilter(FILTER_NAME);
                }
                FILTER_DEPTH.remove();
            } else {
                FILTER_DEPTH.set(nextDepth);
            }
        }
    }

    private String currentTenantId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_PLATFORM_ADMIN".equals(authority.getAuthority()))) {
            return null;
        }
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            String tenantId = JwtTenantResolver.extractTenantId(jwt);
            if (tenantId != null && isUuid(tenantId)) {
                return tenantId;
            }
        }
        return null;
    }

    private boolean isUuid(String tenantId) {
        try {
            UUID.fromString(tenantId);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }
}
