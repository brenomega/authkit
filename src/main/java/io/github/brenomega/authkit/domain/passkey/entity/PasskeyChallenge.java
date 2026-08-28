package io.github.brenomega.authkit.domain.passkey.entity;

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

/**
 * Represents short-lived WebAuthn ceremony state shared across application instances.
 *
 * <p>An assertion challenge may omit {@code userId} for discoverable credentials;
 * registration challenges are user-bound. Expiration and single consumption are
 * enforced by a conditional repository update rather than this entity alone.</p>
 */
@Entity
@Table(name = "passkey_challenges")
public class PasskeyChallenge {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Enumerated(EnumType.STRING)
    @Column(name = "ceremony_type", nullable = false, length = 32)
    private PasskeyChallengeType ceremonyType;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "request_json", nullable = false, columnDefinition = "TEXT")
    private String requestJson;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    protected PasskeyChallenge() {
    }

    public PasskeyChallenge(PasskeyChallengeType ceremonyType,
                            UUID userId,
                            String requestJson,
                            Instant createdAt,
                            Instant expiresAt) {
        this.ceremonyType = ceremonyType;
        this.userId = userId;
        this.requestJson = requestJson;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    public UUID getId() {
        return id;
    }

    public PasskeyChallengeType getCeremonyType() {
        return ceremonyType;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getRequestJson() {
        return requestJson;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }
}
