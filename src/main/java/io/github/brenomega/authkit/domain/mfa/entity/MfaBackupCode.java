package io.github.brenomega.authkit.domain.mfa.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Represents a user-bound backup-code digest and its irreversible consumption state.
 * The raw recovery factor is never persisted; repository-level conditional updates
 * provide the single-use transition used during concurrent verification.
 */
@Entity
@Table(name = "mfa_backup_codes")
public class MfaBackupCode {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "code_hash", nullable = false, length = 64, updatable = false)
    private String codeHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "used_at")
    private Instant usedAt;

    protected MfaBackupCode() {
    }

    public MfaBackupCode(UUID userId, UUID tenantId, String codeHash, Instant createdAt) {
        this.userId = userId;
        this.tenantId = tenantId;
        this.codeHash = codeHash;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getUserId() {
        return userId;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }

    public boolean isUsed() {
        return usedAt != null;
    }

    public void markUsed(Instant usedAt) {
        this.usedAt = usedAt;
    }
}
