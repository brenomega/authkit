package io.github.brenomega.authkit.domain.social.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "social_identities")
public class SocialIdentity {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;
    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;
    @Column(name = "provider_id", nullable = false, updatable = false)
    private UUID providerId;
    @Column(name = "issuer", nullable = false, length = 512, updatable = false)
    private String issuer;
    @Column(name = "subject", nullable = false, length = 255, updatable = false)
    private String subject;
    @Column(name = "email_at_link", length = 255, updatable = false)
    private String emailAtLink;
    @Column(name = "email_verified", nullable = false, updatable = false)
    private boolean emailVerified;
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    protected SocialIdentity() {}
    public SocialIdentity(UUID userId, UUID tenantId, UUID providerId, String issuer, String subject,
                          String emailAtLink, boolean emailVerified, Instant now) {
        this.userId = userId; this.tenantId = tenantId; this.providerId = providerId;
        this.issuer = issuer; this.subject = subject; this.emailAtLink = emailAtLink;
        this.emailVerified = emailVerified; this.createdAt = now; this.lastLoginAt = now;
    }
    public UUID getId() { return id; }
    public UUID getUserId() { return userId; }
    public UUID getTenantId() { return tenantId; }
    public UUID getProviderId() { return providerId; }
    public String getIssuer() { return issuer; }
    public String getSubject() { return subject; }
    public String getEmailAtLink() { return emailAtLink; }
    public boolean isEmailVerified() { return emailVerified; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastLoginAt() { return lastLoginAt; }
    public void markLogin(Instant now) { lastLoginAt = now; }
}
