package io.github.brenomega.authkit.infrastructure.audit;

import java.time.Instant;
import java.util.UUID;

import org.hibernate.annotations.Immutable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Append-only durable security event for abuse detection, forensics, and privacy audits.
 */
@Entity
@Immutable
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "occurred_at", nullable = false, updatable = false)
    private Instant occurredAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 80, updatable = false)
    private SecurityEventType eventType;

    @Enumerated(EnumType.STRING)
    @Column(name = "outcome", nullable = false, length = 20, updatable = false)
    private SecurityEventOutcome outcome;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 20, updatable = false)
    private SecurityEventSeverity severity;

    @Column(name = "actor_user_id", updatable = false)
    private UUID actorUserId;

    @Column(name = "target_user_id", updatable = false)
    private UUID targetUserId;

    @Column(name = "tenant_id", updatable = false)
    private UUID tenantId;

    @Column(name = "email_hash", length = 64, updatable = false)
    private String emailHash;

    @Column(name = "email_masked", length = 320, updatable = false)
    private String emailMasked;

    @Column(name = "client_ip_hash", length = 64, updatable = false)
    private String clientIpHash;

    @Column(name = "client_ip_masked", length = 80, updatable = false)
    private String clientIpMasked;

    @Column(name = "user_agent_hash", length = 64, updatable = false)
    private String userAgentHash;

    @Column(name = "request_method", length = 16, updatable = false)
    private String requestMethod;

    @Column(name = "request_path", length = 512, updatable = false)
    private String requestPath;

    @Column(name = "reason", length = 120, updatable = false)
    private String reason;

    @Column(name = "metadata_json", columnDefinition = "TEXT", updatable = false)
    private String metadataJson;

    @Column(name = "event_hash", nullable = false, length = 64, updatable = false)
    private String eventHash;

    protected SecurityEvent() {
    }

    SecurityEvent(Instant occurredAt,
                  SecurityEventType eventType,
                  SecurityEventOutcome outcome,
                  SecurityEventSeverity severity,
                  UUID actorUserId,
                  UUID targetUserId,
                  UUID tenantId,
                  String emailHash,
                  String emailMasked,
                  String clientIpHash,
                  String clientIpMasked,
                  String userAgentHash,
                  String requestMethod,
                  String requestPath,
                  String reason,
                  String metadataJson,
                  String eventHash) {
        this.occurredAt = occurredAt;
        this.eventType = eventType;
        this.outcome = outcome;
        this.severity = severity;
        this.actorUserId = actorUserId;
        this.targetUserId = targetUserId;
        this.tenantId = tenantId;
        this.emailHash = emailHash;
        this.emailMasked = emailMasked;
        this.clientIpHash = clientIpHash;
        this.clientIpMasked = clientIpMasked;
        this.userAgentHash = userAgentHash;
        this.requestMethod = requestMethod;
        this.requestPath = requestPath;
        this.reason = reason;
        this.metadataJson = metadataJson;
        this.eventHash = eventHash;
    }

    public UUID getId() {
        return id;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public SecurityEventType getEventType() {
        return eventType;
    }

    public SecurityEventOutcome getOutcome() {
        return outcome;
    }

    public SecurityEventSeverity getSeverity() {
        return severity;
    }

    public UUID getActorUserId() {
        return actorUserId;
    }

    public UUID getTargetUserId() {
        return targetUserId;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getEmailHash() {
        return emailHash;
    }

    public String getEmailMasked() {
        return emailMasked;
    }

    public String getClientIpHash() {
        return clientIpHash;
    }

    public String getClientIpMasked() {
        return clientIpMasked;
    }

    public String getUserAgentHash() {
        return userAgentHash;
    }

    public String getRequestMethod() {
        return requestMethod;
    }

    public String getRequestPath() {
        return requestPath;
    }

    public String getReason() {
        return reason;
    }

    public String getMetadataJson() {
        return metadataJson;
    }

    public String getEventHash() {
        return eventHash;
    }
}
