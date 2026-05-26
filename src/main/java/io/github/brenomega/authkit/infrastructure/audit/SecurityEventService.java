package io.github.brenomega.authkit.infrastructure.audit;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.EmailMasker;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.infrastructure.network.ip.IpMasker;
import io.github.brenomega.authkit.infrastructure.network.ip.NetworkIpResolver;
import io.github.brenomega.authkit.infrastructure.security.AuthProperties;

/**
 * Builds privacy-safe security events and persists them through a bounded writer.
 */
@Service
public class SecurityEventService {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventService.class);
    private static final Logger alertLog = LoggerFactory.getLogger("SECURITY_ALERT");
    private static final int MAX_REASON_LENGTH = 120;
    private static final int MAX_PATH_LENGTH = 512;
    private static final int MAX_METADATA_KEY_LENGTH = 64;
    private static final int MAX_METADATA_VALUE_LENGTH = 160;
    private static final String REDACTED = "[REDACTED]";
    private static final Set<String> SENSITIVE_METADATA_TOKENS = Set.of(
            "password", "passwd", "secret", "token", "jwt", "authorization", "cookie",
            "session", "csrf", "credential", "key", "otp", "totp", "webauthn");

    private final SecurityEventWriter eventWriter;
    private final ThreadPoolTaskExecutor eventExecutor;
    private final NetworkIpResolver networkIpResolver;
    private final MeterRegistry meterRegistry;
    private final ObjectMapper objectMapper;
    private final AuthProperties authProperties;
    private final AuditDigestService auditDigestService;

    public SecurityEventService(SecurityEventWriter eventWriter,
                                @Qualifier("securityEventExecutor") ThreadPoolTaskExecutor eventExecutor,
                                NetworkIpResolver networkIpResolver,
                                MeterRegistry meterRegistry,
                                ObjectMapper objectMapper,
                                AuthProperties authProperties,
                                AuditDigestService auditDigestService) {
        this.eventWriter = eventWriter;
        this.eventExecutor = eventExecutor;
        this.networkIpResolver = networkIpResolver;
        this.meterRegistry = meterRegistry;
        this.objectMapper = objectMapper;
        this.authProperties = authProperties;
        this.auditDigestService = auditDigestService;
    }

    public void recordForAuthenticatedUser(SecurityEventType type,
                                           SecurityEventOutcome outcome,
                                           SecurityEventSeverity severity,
                                           User user,
                                           String reason) {
        record(type, outcome, severity, user.getId(), user.getId(), user.getTenantId(), user.getEmail(), reason, Map.of());
    }

    public void recordForAuthenticatedUser(SecurityEventType type,
                                           SecurityEventOutcome outcome,
                                           SecurityEventSeverity severity,
                                           User user,
                                           String reason,
                                           Map<String, String> metadata) {
        record(type, outcome, severity, user.getId(), user.getId(), user.getTenantId(), user.getEmail(), reason, metadata);
    }

    public void recordForTargetUser(SecurityEventType type,
                                    SecurityEventOutcome outcome,
                                    SecurityEventSeverity severity,
                                    User user,
                                    String reason) {
        record(type, outcome, severity, null, user.getId(), user.getTenantId(), user.getEmail(), reason, Map.of());
    }

    public void recordForTargetUser(SecurityEventType type,
                                    SecurityEventOutcome outcome,
                                    SecurityEventSeverity severity,
                                    User user,
                                    String reason,
                                    Map<String, String> metadata) {
        record(type, outcome, severity, null, user.getId(), user.getTenantId(), user.getEmail(), reason, metadata);
    }

    public void recordForEmail(SecurityEventType type,
                               SecurityEventOutcome outcome,
                               SecurityEventSeverity severity,
                               String email,
                               String reason) {
        record(type, outcome, severity, null, null, null, email, reason, Map.of());
    }

    public void recordForEmail(SecurityEventType type,
                               SecurityEventOutcome outcome,
                               SecurityEventSeverity severity,
                               String email,
                               String reason,
                               Map<String, String> metadata) {
        record(type, outcome, severity, null, null, null, email, reason, metadata);
    }

    public void record(SecurityEventType type,
                       SecurityEventOutcome outcome,
                       SecurityEventSeverity severity,
                       UUID actorUserId,
                       UUID targetUserId,
                       UUID tenantId,
                       String email,
                       String reason,
                       Map<String, String> metadata) {
        Instant occurredAt = Instant.now();
        RequestSnapshot request = currentRequestSnapshot();
        String normalizedEmail = normalizeNullable(email);
        String emailHash = hashNullable(normalizedEmail);
        String metadataJson = toJson(metadata);
        String storedReason = truncate(reason, MAX_REASON_LENGTH);

        String eventHash = eventHash(
                occurredAt,
                type,
                outcome,
                severity,
                actorUserId,
                targetUserId,
                tenantId,
                emailHash,
                request.clientIpHash(),
                request.userAgentHash(),
                request.method(),
                request.path(),
                storedReason,
                metadataJson);

        SecurityEvent event = new SecurityEvent(
                occurredAt,
                type,
                outcome,
                severity,
                actorUserId,
                targetUserId,
                tenantId,
                emailHash,
                normalizedEmail == null ? null : EmailMasker.mask(normalizedEmail),
                request.clientIpHash(),
                request.clientIpMasked(),
                request.userAgentHash(),
                request.method(),
                request.path(),
                storedReason,
                metadataJson,
                eventHash);

        meterRegistry.counter("security.events", "type", type.name(), "outcome", outcome.name(), "severity", severity.name())
                .increment();
        recordSpecificMetric(type, storedReason);
        persist(event);
        alertIfNeeded(type, outcome, severity, eventHash);
    }

    private void persist(SecurityEvent event) {
        if (!authProperties.getAudit().isAsyncEnabled()) {
            persistDirect(event);
            return;
        }

        try {
            eventExecutor.execute(() -> persistDirect(event));
        } catch (TaskRejectedException ex) {
            meterRegistry.counter("security.events.overloaded",
                    "type", event.getEventType().name(),
                    "severity", event.getSeverity().name()).increment();

            if (authProperties.getAudit().isPersistSynchronouslyOnOverload()) {
                meterRegistry.counter("security.events.fallback.persisted",
                        "type", event.getEventType().name(),
                        "severity", event.getSeverity().name()).increment();
                persistDirect(event);
                return;
            }

            meterRegistry.counter("security.events.dropped",
                    "type", event.getEventType().name(),
                    "severity", event.getSeverity().name(),
                    "reason", "queue_saturated").increment();
            log.warn("Security event writer queue saturated; dropped event type={} severity={} eventHash={}",
                    event.getEventType(), event.getSeverity(), event.getEventHash());
        }
    }

    private void persistDirect(SecurityEvent event) {
        try {
            eventWriter.persist(event);
        } catch (RuntimeException ex) {
            meterRegistry.counter("security.infrastructure.failure", "component", "security_event_store").increment();
            meterRegistry.counter("security.events.dropped",
                    "type", event.getEventType().name(),
                    "severity", event.getSeverity().name(),
                    "reason", "persistence_failure").increment();
            log.error("Security event persistence failed type={} severity={} eventHash={}",
                    event.getEventType(), event.getSeverity(), event.getEventHash(), ex);
        }
    }

    private void recordSpecificMetric(SecurityEventType type, String reason) {
        switch (type) {
            case LOGIN_FAILURE -> meterRegistry.counter("security.login.failed").increment();
            case ACCOUNT_LOCKED -> meterRegistry.counter("security.account.locked").increment();
            case PASSWORD_RESET_FAILED -> meterRegistry.counter("security.password_reset.failed").increment();
            case REFRESH_TOKEN_REUSE_DETECTED -> meterRegistry.counter("security.refresh_token.reuse").increment();
            case MFA_CHALLENGE_ISSUED -> meterRegistry.counter("security.mfa.challenge.issued").increment();
            case MFA_CHALLENGE_VERIFIED -> meterRegistry.counter("security.mfa.login.verified").increment();
            case MFA_CHALLENGE_FAILED -> recordMfaFailureMetric(reason);
            case MFA_BACKUP_CODE_USED -> meterRegistry.counter("security.mfa.backup_code.used").increment();
            case MFA_BACKUP_CODES_REGENERATED -> meterRegistry.counter("security.mfa.backup_codes.regenerated").increment();
            case MFA_CHANGED -> meterRegistry.counter("security.mfa.changed").increment();
            default -> {
            }
        }
    }

    private void recordMfaFailureMetric(String reason) {
        meterRegistry.counter("security.mfa.challenge.failed").increment();
        String normalizedReason = reason == null ? "" : reason.toLowerCase(java.util.Locale.ROOT);
        if (normalizedReason.startsWith("login_mfa") || normalizedReason.contains("mfa_challenge")) {
            meterRegistry.counter("security.mfa.login.failed").increment();
            return;
        }
        meterRegistry.counter("security.mfa.step_up.failed").increment();
    }

    private void alertIfNeeded(SecurityEventType type,
                               SecurityEventOutcome outcome,
                               SecurityEventSeverity severity,
                               String eventHash) {
        if (severity == SecurityEventSeverity.HIGH || severity == SecurityEventSeverity.CRITICAL) {
            alertLog.warn("Security event alert type={} outcome={} severity={} eventHash={}",
                    type, outcome, severity, eventHash);
        }
    }

    private RequestSnapshot currentRequestSnapshot() {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) {
            return new RequestSnapshot(null, null, null, null, null);
        }

        HttpServletRequest request = attributes.getRequest();
        String clientIp = networkIpResolver.resolveClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        return new RequestSnapshot(
                truncate(request.getMethod(), 16),
                truncate(request.getRequestURI(), MAX_PATH_LENGTH),
                hashNullable(clientIp),
                clientIp == null ? null : IpMasker.mask(clientIp),
                hashNullable(userAgent));
    }

    private String toJson(Map<String, String> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }

        TreeMap<String, String> sanitized = new TreeMap<>();
        metadata.forEach((key, value) -> {
            if (key != null && value != null) {
                String storedKey = truncate(key, MAX_METADATA_KEY_LENGTH);
                String storedValue = isSensitiveMetadataKey(key) ? REDACTED : truncate(value, MAX_METADATA_VALUE_LENGTH);
                sanitized.put(storedKey, storedValue);
            }
        });

        if (sanitized.isEmpty()) {
            return null;
        }

        try {
            return objectMapper.writeValueAsString(sanitized);
        } catch (JsonProcessingException ex) {
            log.warn("Security event metadata serialization failed; dropping metadata.");
            return null;
        }
    }

    private boolean isSensitiveMetadataKey(String key) {
        String normalized = key.toLowerCase(java.util.Locale.ROOT);
        return SENSITIVE_METADATA_TOKENS.stream().anyMatch(normalized::contains);
    }

    private String normalizeNullable(String email) {
        if (email == null || email.isBlank()) {
            return null;
        }
        return EmailNormalizer.normalize(email);
    }

    private String hashNullable(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return auditDigestService.hmacHex(value);
    }

    private String eventHash(Instant occurredAt,
                             SecurityEventType type,
                             SecurityEventOutcome outcome,
                             SecurityEventSeverity severity,
                             UUID actorUserId,
                             UUID targetUserId,
                             UUID tenantId,
                             String emailHash,
                             String clientIpHash,
                             String userAgentHash,
                             String method,
                             String path,
                             String reason,
                             String metadataJson) {
        String canonical = String.join("|",
                occurredAt.toString(),
                stringValue(type),
                stringValue(outcome),
                stringValue(severity),
                stringValue(actorUserId),
                stringValue(targetUserId),
                stringValue(tenantId),
                stringValue(emailHash),
                stringValue(clientIpHash),
                stringValue(userAgentHash),
                stringValue(method),
                stringValue(path),
                stringValue(reason),
                stringValue(metadataJson));

        return auditDigestService.hmacHex(canonical);
    }

    private String stringValue(Object value) {
        return value == null ? "" : value.toString();
    }

    private String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    private record RequestSnapshot(
            String method,
            String path,
            String clientIpHash,
            String clientIpMasked,
            String userAgentHash) {
    }
}
