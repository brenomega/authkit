package io.github.brenomega.authkit.domain.social.entity;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "social_identity_providers")
public class SocialIdentityProvider {
    @Id @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "provider_key", nullable = false, unique = true, length = 64, updatable = false)
    private String providerKey;
    @Column(name = "display_name", nullable = false, length = 120)
    private String displayName;
    @Enumerated(EnumType.STRING)
    @Column(name = "provider_type", nullable = false, length = 32)
    private SocialProviderType providerType;
    @Column(name = "issuer", nullable = false, unique = true, length = 512)
    private String issuer;
    @Column(name = "client_id", nullable = false, length = 255)
    private String clientId;
    @Column(name = "encrypted_client_secret", nullable = false, columnDefinition = "TEXT")
    private String encryptedClientSecret;
    @Column(name = "scopes", nullable = false, length = 512)
    private String scopes;
    @Enumerated(EnumType.STRING)
    @Column(name = "client_auth_method", nullable = false, length = 32)
    private OidcClientAuthMethod clientAuthMethod;
    @Column(name = "enabled", nullable = false)
    private boolean enabled;
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
    @Column(name = "disabled_at")
    private Instant disabledAt;

    protected SocialIdentityProvider() {}

    public SocialIdentityProvider(String providerKey, String displayName, SocialProviderType providerType,
                                  String issuer, String clientId, String encryptedClientSecret,
                                  Set<String> scopes, OidcClientAuthMethod clientAuthMethod, Instant now) {
        this.providerKey = providerKey;
        this.displayName = displayName;
        this.providerType = providerType;
        this.issuer = issuer;
        this.clientId = clientId;
        this.encryptedClientSecret = encryptedClientSecret;
        this.scopes = join(scopes);
        this.clientAuthMethod = clientAuthMethod;
        this.enabled = true;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public UUID getId() { return id; }
    public String getProviderKey() { return providerKey; }
    public String getDisplayName() { return displayName; }
    public SocialProviderType getProviderType() { return providerType; }
    public String getIssuer() { return issuer; }
    public String getClientId() { return clientId; }
    public String getEncryptedClientSecret() { return encryptedClientSecret; }
    public Set<String> getScopes() { return split(scopes); }
    public OidcClientAuthMethod getClientAuthMethod() { return clientAuthMethod; }
    public boolean isEnabled() { return enabled && disabledAt == null; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public Instant getDisabledAt() { return disabledAt; }

    public void update(String displayName, String clientId, String encryptedClientSecret,
                       Set<String> scopes, OidcClientAuthMethod clientAuthMethod, Instant now) {
        this.displayName = displayName;
        this.clientId = clientId;
        if (encryptedClientSecret != null) this.encryptedClientSecret = encryptedClientSecret;
        this.scopes = join(scopes);
        this.clientAuthMethod = clientAuthMethod;
        this.updatedAt = now;
    }

    public void disable(Instant now) { enabled = false; disabledAt = now; updatedAt = now; }

    private static String join(Set<String> values) {
        return values.stream().map(String::trim).filter(v -> !v.isBlank()).sorted().collect(Collectors.joining(" "));
    }
    private static Set<String> split(String value) {
        if (value == null || value.isBlank()) return Set.of();
        return Arrays.stream(value.split("\\s+")).collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
