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

/**
 * Emits privacy-conscious structured logs after successful controller mutations.
 *
 * <p>Entries contain principal and tenant identifiers, operation, timestamp, and
 * a masked resolved address; request bodies are never included. Advice runs only
 * after a controller returns normally. These logs are operational signals and do
 * not replace durable {@link io.github.brenomega.authkit.infrastructure.audit.SecurityEvent}
 * persistence.</p>
 *
 * @see NetworkIpResolver
 * @see LoggingAspect
 */
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

    // -------------------------------------------------------------------------
    // Pointcuts — Target state-changing controller operations
    // -------------------------------------------------------------------------

    /**
     * Matches POST mapping methods in controllers.
     */
    @Pointcut("@annotation(org.springframework.web.bind.annotation.PostMapping) && "
            + "within(io.github.brenomega.authkit.controller..*)")
    public void postMappings() {}

    /**
     * Matches PUT mapping methods in controllers.
     */
    @Pointcut("@annotation(org.springframework.web.bind.annotation.PutMapping) && "
            + "within(io.github.brenomega.authkit.controller..*)")
    public void putMappings() {}

    /**
     * Matches PATCH mapping methods in controllers.
     */
    @Pointcut("@annotation(org.springframework.web.bind.annotation.PatchMapping) && "
            + "within(io.github.brenomega.authkit.controller..*)")
    public void patchMappings() {}

    /**
     * Matches DELETE mapping methods in controllers.
     */
    @Pointcut("@annotation(org.springframework.web.bind.annotation.DeleteMapping) && "
            + "within(io.github.brenomega.authkit.controller..*)")
    public void deleteMappings() {}

    /**
     * Union of all state-changing pointcuts.
     */
    @Pointcut("postMappings() || putMappings() || patchMappings() || deleteMappings()")
    public void stateChangingOperations() {}

    // -------------------------------------------------------------------------
    // Advice — Emit structured JSON audit log on successful completion
    // -------------------------------------------------------------------------

    /**
     * Emits a JSON-structured audit log entry after a state-changing operation
     * completes successfully (DT 3.4.8, RN 04).
     *
     * @param joinPoint the intercepted join point
     */
    @AfterReturning("stateChangingOperations()")
    public void auditStateChange(JoinPoint joinPoint) {
        String userId = "anonymous";
        String tenantId = "unknown";
        String clientIp = "unknown";
        String httpMethod = "UNKNOWN";
        String requestUri = "unknown";

        // Extract user context from SecurityContextHolder
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            userId = jwt.getSubject();
            tenantId = JwtTenantResolver.extractTenantId(jwt);
            if (tenantId == null) {
                tenantId = "unknown";
            }
        }

        // Extract HTTP request details
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
