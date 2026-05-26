package io.github.brenomega.authkit.domain.passkey.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Persisted WebAuthn credential material. Private key material never leaves the
 * authenticator; this table stores only public credential metadata.
 */
@Entity
@Table(name = "passkey_credentials")
public class PasskeyCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "credential_id", nullable = false, unique = true, length = 512, updatable = false)
    private String credentialId;

    @Column(name = "public_key_cose", nullable = false, columnDefinition = "TEXT")
    private String publicKeyCose;

    @Column(name = "signature_count", nullable = false)
    private long signatureCount;

    @Column(name = "transports", length = 255)
    private String transports;

    @Column(name = "label", length = 100)
    private String label;

    @Column(name = "discoverable", nullable = false)
    private boolean discoverable;

    @Column(name = "backup_eligible", nullable = false)
    private boolean backupEligible;

    @Column(name = "backed_up", nullable = false)
    private boolean backedUp;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "disabled_at")
    private Instant disabledAt;

    protected PasskeyCredential() {
    }

    public PasskeyCredential(UUID userId,
                             UUID tenantId,
                             String credentialId,
                             String publicKeyCose,
                             long signatureCount,
                             String transports,
                             String label,
                             boolean discoverable,
                             boolean backupEligible,
                             boolean backedUp,
                             Instant createdAt) {
        this.userId = userId;
        this.tenantId = tenantId;
        this.credentialId = credentialId;
        this.publicKeyCose = publicKeyCose;
        this.signatureCount = signatureCount;
        this.transports = transports;
        this.label = label;
        this.discoverable = discoverable;
        this.backupEligible = backupEligible;
        this.backedUp = backedUp;
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

    public String getCredentialId() {
        return credentialId;
    }

    public String getPublicKeyCose() {
        return publicKeyCose;
    }

    public long getSignatureCount() {
        return signatureCount;
    }

    public String getTransports() {
        return transports;
    }

    public String getLabel() {
        return label;
    }

    public boolean isDiscoverable() {
        return discoverable;
    }

    public boolean isBackupEligible() {
        return backupEligible;
    }

    public boolean isBackedUp() {
        return backedUp;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getLastUsedAt() {
        return lastUsedAt;
    }

    public Instant getDisabledAt() {
        return disabledAt;
    }

    public boolean isActive() {
        return disabledAt == null;
    }

    public void markUsed(long newSignatureCount, boolean backupEligible, boolean backedUp, Instant usedAt) {
        this.signatureCount = newSignatureCount;
        this.backupEligible = backupEligible;
        this.backedUp = backedUp;
        this.lastUsedAt = usedAt;
    }

    public void disable(Instant disabledAt) {
        if (this.disabledAt == null) {
            this.disabledAt = disabledAt;
        }
    }
}
