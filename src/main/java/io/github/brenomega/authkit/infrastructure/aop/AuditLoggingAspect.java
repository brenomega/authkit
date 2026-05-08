package io.github.brenomega.authkit.infrastructure.aop;

import java.time.Instant;

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

import io.github.brenomega.authkit.infrastructure.network.ip.NetworkIpResolver;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Structured audit logging aspect for state-changing controller operations (DT 3.4.8, RN 04).
 *
 * <p>Intercepts all {@code @PostMapping}, {@code @PutMapping}, {@code @PatchMapping}, and
 * {@code @DeleteMapping} methods across {@code AuthController} and {@code UserController}
 * to produce JSON-structured audit logs.</p>
 *
 * <h3>Captured Fields</h3>
 * <ul>
 *   <li>{@code userId} — from {@code SecurityContextHolder} JWT {@code sub} claim</li>
 *   <li>{@code action} — HTTP method and endpoint path</li>
 *   <li>{@code tenant_id} — from JWT {@code tenantId} claim</li>
 *   <li>{@code client_ip} — resolved via {@link NetworkIPResolver} (DT 3.2.17)</li>
 *   <li>{@code timestamp} — ISO-8601 formatted instant</li>
 * </ul>
 *
 * <p><strong>Sanitization (DT 3.4.1):</strong> Request bodies are NEVER logged to prevent
 * leakage of passwords, tokens, or other sensitive data.</p>
 *
 * @see NetworkIPResolver
 * @see LoggingAspect
 */
@Aspect
@Component
public class AuditLoggingAspect {

    private static final Logger auditLog = LoggerFactory.getLogger("AUDIT");

    private final NetworkIpResolver networkIpResolver;

    public AuditLoggingAspect(NetworkIpResolver networkIpResolver) {
        this.networkIpResolver = networkIpResolver;
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
            tenantId = jwt.getClaimAsString("tenantId") != null
                    ? jwt.getClaimAsString("tenantId")
                    : "unknown";
        }

        // Extract HTTP request details
        ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            HttpServletRequest request = attrs.getRequest();
            clientIp = networkIpResolver.resolveClientIp(request);
            httpMethod = request.getMethod();
            requestUri = request.getRequestURI();
        }

        String timestamp = Instant.now().toString();

        // Emit structured JSON audit log (DT 3.4.8)
        // Appended to stdout for capture by external aggregators (CloudWatch)
        auditLog.info(
                "{\"userId\":\"{}\",\"action\":\"{} {}\",\"tenant_id\":\"{}\",\"client_ip\":\"{}\",\"timestamp\":\"{}\"}",
                userId, httpMethod, requestUri, tenantId, clientIp, timestamp
        );
    }
}
