package io.github.brenomega.authkit.infrastructure.queue.outbox;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import io.github.brenomega.authkit.infrastructure.queue.EmailPayload;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;

@Entity
@Table(name = "email_outbox")
public class EmailOutboxMessage {

    private static final int MAX_ERROR_LENGTH = 1000;

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "recipient", nullable = false, length = 320)
    private String recipient;

    @Column(name = "subject", nullable = false, length = 255)
    private String subject;

    @Column(name = "body", nullable = false, columnDefinition = "TEXT")
    private String body;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private EmailOutboxStatus status = EmailOutboxStatus.PENDING;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "next_attempt_at", nullable = false)
    private Instant nextAttemptAt;

    @Column(name = "locked_at")
    private Instant lockedAt;

    @Column(name = "last_error", length = MAX_ERROR_LENGTH)
    private String lastError;

    @Column(name = "provider_message_id", length = 255)
    private String providerMessageId;

    @Column(name = "delivered_at")
    private Instant deliveredAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected EmailOutboxMessage() {
    }

    private EmailOutboxMessage(EmailPayload payload, Instant now) {
        this.recipient = payload.to();
        this.subject = payload.subject();
        this.body = payload.htmlBody();
        this.status = EmailOutboxStatus.PENDING;
        this.nextAttemptAt = now;
    }

    public static EmailOutboxMessage pending(EmailPayload payload, Instant now) {
        return new EmailOutboxMessage(payload, now);
    }

    @PrePersist
    void prePersist() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
        if (this.nextAttemptAt == null) {
            this.nextAttemptAt = now;
        }
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = Instant.now();
    }

    public EmailPayload toPayload() {
        return new EmailPayload(id, recipient, subject, body);
    }

    public void markProcessing(Instant now) {
        this.status = EmailOutboxStatus.PROCESSING;
        this.lockedAt = now;
        this.attempts++;
        this.lastError = null;
    }

    public void markQueued(Instant now, Duration deliveryTimeout) {
        this.status = EmailOutboxStatus.QUEUED;
        this.lockedAt = null;
        this.lastError = null;
        this.nextAttemptAt = now.plus(deliveryTimeout);
    }

    public void markSent(String providerMessageId, Instant now) {
        this.status = EmailOutboxStatus.SENT;
        this.lockedAt = null;
        this.lastError = null;
        this.providerMessageId = providerMessageId;
        this.deliveredAt = now;
    }

    public void markFailed(String error, Instant now) {
        this.status = EmailOutboxStatus.FAILED;
        this.lockedAt = null;
        this.lastError = truncate(error);
        this.nextAttemptAt = now.plus(backoffDelay());
    }

    private Duration backoffDelay() {
        long delaySeconds = Math.min(3600, 60L * (1L << Math.min(attempts, 5)));
        return Duration.ofSeconds(delaySeconds);
    }

    private static String truncate(String value) {
        if (value == null) {
            return null;
        }
        return value.length() <= MAX_ERROR_LENGTH ? value : value.substring(0, MAX_ERROR_LENGTH);
    }

    public UUID getId() {
        return id;
    }

    public String getRecipient() {
        return recipient;
    }

    public String getSubject() {
        return subject;
    }

    public String getBody() {
        return body;
    }

    public EmailOutboxStatus getStatus() {
        return status;
    }

    public int getAttempts() {
        return attempts;
    }

    public Instant getNextAttemptAt() {
        return nextAttemptAt;
    }

    public Instant getLockedAt() {
        return lockedAt;
    }

    public String getLastError() {
        return lastError;
    }

    public String getProviderMessageId() {
        return providerMessageId;
    }

    public Instant getDeliveredAt() {
        return deliveredAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
