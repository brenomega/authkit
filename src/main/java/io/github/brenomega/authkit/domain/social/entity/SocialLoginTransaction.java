package io.github.brenomega.authkit.domain.social.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "social_login_transactions")
public class SocialLoginTransaction {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(name = "state_hash", nullable = false, unique = true, length = 64, updatable = false)
    private String stateHash;
    @Column(name = "provider_id", nullable = false, updatable = false)
    private UUID providerId;
    @Enumerated(EnumType.STRING)
    @Column(name = "purpose", nullable = false, length = 16, updatable = false)
    private SocialLoginPurpose purpose;
    @Column(name = "user_id", updatable = false)
    private UUID userId;
    @Column(name = "nonce", nullable = false, length = 128, updatable = false)
    private String nonce;
    @Column(name = "encrypted_verifier", nullable = false, columnDefinition = "TEXT", updatable = false)
    private String encryptedVerifier;
    @Column(name = "terms_accepted", nullable = false, updatable = false)
    private boolean termsAccepted;
    @Column(name = "privacy_accepted", nullable = false, updatable = false)
    private boolean privacyAccepted;
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;
    @Column(name = "consumed_at")
    private Instant consumedAt;

    protected SocialLoginTransaction() {}
    public SocialLoginTransaction(String stateHash, UUID providerId, SocialLoginPurpose purpose, UUID userId,
                                  String nonce, String encryptedVerifier, boolean termsAccepted,
                                  boolean privacyAccepted, Instant now, Instant expiresAt) {
        this.stateHash = stateHash; this.providerId = providerId; this.purpose = purpose; this.userId = userId;
        this.nonce = nonce; this.encryptedVerifier = encryptedVerifier; this.termsAccepted = termsAccepted;
        this.privacyAccepted = privacyAccepted; this.createdAt = now; this.expiresAt = expiresAt;
    }
    public UUID getId() { return id; }
    public String getStateHash() { return stateHash; }
    public UUID getProviderId() { return providerId; }
    public SocialLoginPurpose getPurpose() { return purpose; }
    public UUID getUserId() { return userId; }
    public String getNonce() { return nonce; }
    public String getEncryptedVerifier() { return encryptedVerifier; }
    public boolean isTermsAccepted() { return termsAccepted; }
    public boolean isPrivacyAccepted() { return privacyAccepted; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getConsumedAt() { return consumedAt; }
}
