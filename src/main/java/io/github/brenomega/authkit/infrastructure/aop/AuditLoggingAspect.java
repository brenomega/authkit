package io.github.brenomega.authkit.infrastructure.aop;

import java.time.Instant;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.github.brenomega.authkit.domain.user.util.JwtTenantResolver;
import io.github.brenomega.authkit.infrastructure.network.ip.IpMasker;
import io.github.brenomega.authkit.infrastructure.network.ip.NetworkIpResolver;
import jakarta.servlet.http.HttpServletRequest;

@Aspect
@Component
public class AuditLoggingAspect {

    private static final Logger auditLog = LoggerFactory.getLogger("AUDIT");

    private final NetworkIpResolver networkIpResolver;
    private final ObjectMapper objectMapper;

    public AuditLoggingAspect(NetworkIpResolver networkIpResolver, ObjectMapper objectMapper) {
        this.networkIpResolver = networkIpResolver;
        this.objectMapper = objectMapper;
    }

    @Pointcut("@annotation(org.springframework.web.bind.annotation.PostMapping) && "
            + "within(io.github.brenomega.authkit.controller..*)")
    public void postMappings() {}

    @Pointcut("@annotation(org.springframework.web.bind.annotation.PutMapping) && "
            + "within(io.github.brenomega.authkit.controller..*)")
    public void putMappings() {}

    @Pointcut("@annotation(org.springframework.web.bind.annotation.PatchMapping) && "
            + "within(io.github.brenomega.authkit.controller..*)")
    public void patchMappings() {}

    @Pointcut("@annotation(org.springframework.web.bind.annotation.DeleteMapping) && "
            + "within(io.github.brenomega.authkit.controller..*)")
    public void deleteMappings() {}

    @Pointcut("postMappings() || putMappings() || patchMappings() || deleteMappings()")
    public void stateChangingOperations() {}

    @AfterReturning("stateChangingOperations()")
    public void auditStateChange(JoinPoint joinPoint) {
        String userId = "anonymous";
        String tenantId = "unknown";
        String clientIp = "unknown";
        String httpMethod = "UNKNOWN";
        String requestUri = "unknown";

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            userId = jwt.getSubject();
            tenantId = JwtTenantResolver.extractTenantId(jwt);
            if (tenantId == null) {
                tenantId = "unknown";
            }
        }

        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
            HttpServletRequest request = attrs.getRequest();
            clientIp = IpMasker.mask(networkIpResolver.resolveClientIp(request));
            httpMethod = request.getMethod();
            requestUri = request.getRequestURI();
        }

        Map<String, String> event = Map.of(
                "userId", userId,
                "action", httpMethod + " " + requestUri,
                "tenant_id", tenantId,
                "client_ip", clientIp,
                "timestamp", Instant.now().toString());

        try {
            auditLog.info(objectMapper.writeValueAsString(event));
        } catch (JsonProcessingException ex) {
            auditLog.info("audit_event_serialization_failed");
        }
    }
}
