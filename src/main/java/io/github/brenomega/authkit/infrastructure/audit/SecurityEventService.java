package io.github.brenomega.authkit.infrastructure.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.github.brenomega.authkit.domain.user.entity.User;
import io.github.brenomega.authkit.domain.user.util.EmailNormalizer;
import io.github.brenomega.authkit.domain.user.util.TokenHasher;
import io.github.brenomega.authkit.infrastructure.network.ip.IpMasker;
import io.github.brenomega.authkit.infrastructure.network.ip.NetworkIpResolver;

/**
 * Persists privacy-safe security events in an independent transaction.
 */
@Service
public class SecurityEventService {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventService.class);
    private static final Logger alertLog = LoggerFactory.getLogger("SECURITY_ALERT");
    private static final int MAX_REASON_LENGTH = 120;
    private static final int MAX_PATH_LENGTH = 512;
    private static final int MAX_METADATA_VALUE_LENGTH = 160;

    private final SecurityEventRepository repository;
    private final NetworkIpResolver networkIpResolver;
    private final MeterRegistry meterRegistry;
    private final ObjectMapper objectMapper;

    public SecurityEventService(SecurityEventRepository repository,
                                NetworkIpResolver networkIpResolver,
                                MeterRegistry meterRegistry,
                                ObjectMapper objectMapper) {
        this.repository = repository;
        this.networkIpResolver = networkIpResolver;
        this.meterRegistry = meterRegistry;
        this.objectMapper = objectMapper;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordForUser(SecurityEventType type,
                              SecurityEventOutcome outcome,
                              SecurityEventSeverity severity,
                              User user,
                              String reason) {
        record(type, outcome, severity, user.getId(), user.getId(), user.getTenantId(), user.getEmail(), reason, Map.of());
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordForUser(SecurityEventType type,
                              SecurityEventOutcome outcome,
                              SecurityEventSeverity severity,
                              User user,
                              String reason,
                              Map<String, String> metadata) {
        record(type, outcome, severity, user.getId(), user.getId(), user.getTenantId(), user.getEmail(), reason, metadata);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordForEmail(SecurityEventType type,
                               SecurityEventOutcome outcome,
                               SecurityEventSeverity severity,
                               String email,
                               String reason) {
        record(type, outcome, severity, null, null, null, email, reason, Map.of());
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
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
                hashNullable(normalizedEmail),
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
                hashNullable(normalizedEmail),
                maskEmail(normalizedEmail),
                request.clientIpHash(),
                request.clientIpMasked(),
                request.userAgentHash(),
                request.method(),
                request.path(),
                storedReason,
                metadataJson,
                eventHash);

        repository.save(event);
        meterRegistry.counter("security.events", "type", type.name(), "outcome", outcome.name(), "severity", severity.name())
                .increment();
        recordSpecificMetric(type);
        alertIfNeeded(type, outcome, severity, eventHash);
    }

    private void recordSpecificMetric(SecurityEventType type) {
        switch (type) {
            case LOGIN_FAILURE -> meterRegistry.counter("security.login.failed").increment();
            case ACCOUNT_LOCKED -> meterRegistry.counter("security.account.locked").increment();
            case PASSWORD_RESET_FAILED -> meterRegistry.counter("security.password_reset.failed").increment();
            case REFRESH_TOKEN_REUSE_DETECTED -> meterRegistry.counter("security.refresh_token.reuse").increment();
            default -> {
            }
        }
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
        ServletRequestAttributes attributes =
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
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
                sanitized.put(truncate(key, 64), truncate(value, MAX_METADATA_VALUE_LENGTH));
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

    private String normalizeNullable(String email) {
        if (email == null || email.isBlank()) {
            return null;
        }
        return EmailNormalizer.normalize(email);
    }

    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return null;
        }
        int atIndex = email.indexOf('@');
        String local = email.substring(0, atIndex);
        String domain = email.substring(atIndex);
        return local.charAt(0) + "***" + domain;
    }

    private String hashNullable(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return TokenHasher.sha256Hex(value);
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

        byte[] digest = sha256(canonical);
        StringBuilder hex = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    private byte[] sha256(String canonical) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(canonical.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
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
