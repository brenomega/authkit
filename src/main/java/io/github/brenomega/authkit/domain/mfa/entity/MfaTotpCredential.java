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
 * Encrypted TOTP credential bound to one user and tenant.
 */
@Entity
@Table(name = "mfa_totp_credentials")
public class MfaTotpCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "encrypted_secret", nullable = false, length = 512)
    private String encryptedSecret;

    @Column(name = "confirmed", nullable = false)
    private boolean confirmed;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "confirmed_at")
    private Instant confirmedAt;

    @Column(name = "disabled_at")
    private Instant disabledAt;

    @Column(name = "last_used_time_step")
    private Long lastUsedTimeStep;

    protected MfaTotpCredential() {
    }

    public MfaTotpCredential(UUID userId, UUID tenantId, String encryptedSecret, Instant createdAt) {
        this.userId = userId;
        this.tenantId = tenantId;
        this.encryptedSecret = encryptedSecret;
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

    public String getEncryptedSecret() {
        return encryptedSecret;
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getConfirmedAt() {
        return confirmedAt;
    }

    public Instant getDisabledAt() {
        return disabledAt;
    }

    public Long getLastUsedTimeStep() {
        return lastUsedTimeStep;
    }

    public boolean isActive() {
        return confirmed && disabledAt == null;
    }

    public void confirm(Instant confirmedAt) {
        this.confirmed = true;
        this.confirmedAt = confirmedAt;
    }

    public void disable(Instant disabledAt) {
        this.disabledAt = disabledAt;
    }

    public void markTimeStepUsed(long timeStep) {
        this.lastUsedTimeStep = timeStep;
    }
}
