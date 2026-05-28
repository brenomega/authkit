package io.github.brenomega.authkit.domain.oauth.entity;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "oauth_clients")
public class OAuthClient {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant_id")
    private UUID tenantId;

    @Column(name = "client_id", nullable = false, unique = true, length = 128, updatable = false)
    private String clientId;

    @Column(name = "client_secret_hash")
    private String clientSecretHash;

    @Column(name = "public_client", nullable = false)
    private boolean publicClient;

    @Column(name = "display_name", nullable = false, length = 120)
    private String displayName;

    @Column(name = "redirect_uris", nullable = false, columnDefinition = "TEXT")
    private String redirectUris;

    @Column(name = "scopes", nullable = false, columnDefinition = "TEXT")
    private String scopes;

    @Column(name = "require_pkce", nullable = false)
    private boolean requirePkce;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "disabled_at")
    private Instant disabledAt;

    protected OAuthClient() {
    }

    public OAuthClient(UUID tenantId,
                       String clientId,
                       String clientSecretHash,
                       boolean publicClient,
                       String displayName,
                       Set<String> redirectUris,
                       Set<String> scopes,
                       boolean requirePkce,
                       Instant now) {
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecretHash = clientSecretHash;
        this.publicClient = publicClient;
        this.displayName = displayName;
        this.redirectUris = join(redirectUris);
        this.scopes = join(scopes);
        this.requirePkce = requirePkce;
        this.enabled = true;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecretHash() {
        return clientSecretHash;
    }

    public boolean isPublicClient() {
        return publicClient;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Set<String> getRedirectUris() {
        return split(redirectUris);
    }

    public Set<String> getScopes() {
        return split(scopes);
    }

    public boolean isRequirePkce() {
        return requirePkce;
    }

    public boolean isEnabled() {
        return enabled && disabledAt == null;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getDisabledAt() {
        return disabledAt;
    }

    public void update(String displayName, Set<String> redirectUris, Set<String> scopes, boolean requirePkce, Instant now) {
        this.displayName = displayName;
        this.redirectUris = join(redirectUris);
        this.scopes = join(scopes);
        this.requirePkce = requirePkce;
        this.updatedAt = now;
    }

    public void rotateSecret(String clientSecretHash, Instant now) {
        if (publicClient || clientSecretHash == null || clientSecretHash.isBlank()) {
            throw new IllegalStateException("Only confidential OAuth clients can rotate secrets");
        }
        this.clientSecretHash = clientSecretHash;
        this.updatedAt = now;
    }

    public void disable(Instant now) {
        this.enabled = false;
        this.disabledAt = now;
        this.updatedAt = now;
    }

    private static String join(Set<String> values) {
        return values.stream()
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .sorted()
                .collect(Collectors.joining("\n"));
    }

    private static Set<String> split(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.split("\\R"))
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
