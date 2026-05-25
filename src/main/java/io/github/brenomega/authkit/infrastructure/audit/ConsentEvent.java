package io.github.brenomega.authkit.infrastructure.audit;

import java.time.Instant;
import java.util.UUID;

import org.hibernate.annotations.Immutable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Immutable
@Table(name = "consent_events")
public class ConsentEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "terms_version", nullable = false, length = 64, updatable = false)
    private String termsVersion;

    @Column(name = "privacy_policy_version", nullable = false, length = 64, updatable = false)
    private String privacyPolicyVersion;

    @Column(name = "lawful_basis", nullable = false, length = 64, updatable = false)
    private String lawfulBasis;

    @Column(name = "accepted_at", nullable = false, updatable = false)
    private Instant acceptedAt;

    @Column(name = "recorded_at", nullable = false, updatable = false)
    private Instant recordedAt;

    @Column(name = "event_hash", nullable = false, length = 64, updatable = false)
    private String eventHash;

    protected ConsentEvent() {
    }

    ConsentEvent(UUID userId,
                 UUID tenantId,
                 String termsVersion,
                 String privacyPolicyVersion,
                 String lawfulBasis,
                 Instant acceptedAt,
                 Instant recordedAt,
                 String eventHash) {
        this.userId = userId;
        this.tenantId = tenantId;
        this.termsVersion = termsVersion;
        this.privacyPolicyVersion = privacyPolicyVersion;
        this.lawfulBasis = lawfulBasis;
        this.acceptedAt = acceptedAt;
        this.recordedAt = recordedAt;
        this.eventHash = eventHash;
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

    public String getTermsVersion() {
        return termsVersion;
    }

    public String getPrivacyPolicyVersion() {
        return privacyPolicyVersion;
    }

    public String getLawfulBasis() {
        return lawfulBasis;
    }

    public Instant getAcceptedAt() {
        return acceptedAt;
    }

    public Instant getRecordedAt() {
        return recordedAt;
    }

    public String getEventHash() {
        return eventHash;
    }
}
