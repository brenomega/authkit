package io.github.brenomega.authkit.infrastructure.persistence.securityeffects;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;

/** Durable, idempotent intent for reconciling a committed SQL security mutation. */
@Entity
@Table(name = "security_effect_outbox")
public class SecurityEffectTask {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(name = "effect_type", nullable = false, length = 48)
    private SecurityEffectType effectType;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "target_version")
    private Long targetVersion;

    @Column(name = "preserved_session_jti", length = 36)
    private String preservedSessionJti;

    @Column(name = "recovery_email_digest", length = 64)
    private String recoveryEmailDigest;

    @Column(name = "recovery_token_digest", length = 64)
    private String recoveryTokenDigest;
    @Column(name = "recovery_expires_at")
    private Instant recoveryExpiresAt;
    @Column(name = "email_message_id")
    private UUID emailMessageId;

    public static SecurityEffectTask activateRecoveryToken(UUID userId, long version,
            String emailDigest, String tokenDigest, Instant expiresAt, UUID messageId) {
        SecurityEffectTask task = revokeRecoveryToken(emailDigest);
        task.effectType = SecurityEffectType.ACTIVATE_RECOVERY_TOKEN;
        task.userId = userId;
        task.targetVersion = version;
        task.recoveryTokenDigest = tokenDigest;
        task.recoveryExpiresAt = expiresAt;
        task.emailMessageId = messageId;
        return task;
    }

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private SecurityEffectStatus status;

    @Column(nullable = false)
    private int attempts;

    @Column(name = "next_attempt_at", nullable = false)
    private Instant nextAttemptAt;

    @Column(name = "locked_at")
    private Instant lockedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "last_error", length = 1000)
    private String lastError;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected SecurityEffectTask() {
    }

    public static SecurityEffectTask revokeStaleSessions(
            UUID userId, long targetVersion, String preservedSessionJti) {
        SecurityEffectTask task = new SecurityEffectTask();
        task.id = UUID.randomUUID();
        task.effectType = SecurityEffectType.REVOKE_STALE_SESSIONS;
        task.userId = userId;
        task.targetVersion = targetVersion;
        task.preservedSessionJti = preservedSessionJti;
        task.status = SecurityEffectStatus.PENDING;
        return task;
    }

    public static SecurityEffectTask revokeRecoveryToken(String emailDigest) {
        SecurityEffectTask task = new SecurityEffectTask();
        task.id = UUID.randomUUID();
        task.effectType = SecurityEffectType.REVOKE_RECOVERY_TOKEN;
        task.recoveryEmailDigest = emailDigest;
        task.status = SecurityEffectStatus.PENDING;
        return task;
    }

    @PrePersist
    void prePersist() {
        Instant now = Instant.now();
        createdAt = now;
        updatedAt = now;
        nextAttemptAt = now;
    }

    @PreUpdate
    void preUpdate() {
        updatedAt = Instant.now();
    }

    public boolean claimableAt(Instant now, Instant staleBefore) {
        return ((status == SecurityEffectStatus.PENDING || status == SecurityEffectStatus.FAILED)
                && !nextAttemptAt.isAfter(now))
                || (status == SecurityEffectStatus.PROCESSING && lockedAt != null
                && !lockedAt.isAfter(staleBefore));
    }

    public void markProcessing(Instant now) {
        status = SecurityEffectStatus.PROCESSING;
        lockedAt = now;
        attempts++;
        lastError = null;
    }

    public void markCompleted(Instant now) {
        status = SecurityEffectStatus.COMPLETED;
        lockedAt = null;
        completedAt = now;
        lastError = null;
    }

    public void markFailed(String error, Instant retryAt) {
        status = SecurityEffectStatus.FAILED;
        lockedAt = null;
        nextAttemptAt = retryAt;
        lastError = error == null ? null : error.substring(0, Math.min(1000, error.length()));
    }

    public UUID getId() { return id; }
    public SecurityEffectType getEffectType() { return effectType; }
    public UUID getUserId() { return userId; }
    public Long getTargetVersion() { return targetVersion; }
    public String getPreservedSessionJti() { return preservedSessionJti; }
    public String getRecoveryEmailDigest() { return recoveryEmailDigest; }
    public String getRecoveryTokenDigest() { return recoveryTokenDigest; }
    public Instant getRecoveryExpiresAt() { return recoveryExpiresAt; }
    public UUID getEmailMessageId() { return emailMessageId; }
    public SecurityEffectStatus getStatus() { return status; }
    public int getAttempts() { return attempts; }
    public Instant getCreatedAt() { return createdAt; }
}
