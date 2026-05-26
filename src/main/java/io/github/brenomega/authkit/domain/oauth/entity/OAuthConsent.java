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
@Table(name = "oauth_consents")
public class OAuthConsent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "client_id", nullable = false, length = 128, updatable = false)
    private String clientId;

    @Column(name = "scopes", nullable = false, columnDefinition = "TEXT")
    private String scopes;

    @Column(name = "granted_at", nullable = false)
    private Instant grantedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    protected OAuthConsent() {
    }

    public OAuthConsent(UUID userId, UUID tenantId, String clientId, Set<String> scopes, Instant grantedAt) {
        this.userId = userId;
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.scopes = join(scopes);
        this.grantedAt = grantedAt;
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

    public String getClientId() {
        return clientId;
    }

    public Set<String> getScopes() {
        return split(scopes);
    }

    public Instant getGrantedAt() {
        return grantedAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public boolean includes(Set<String> requestedScopes) {
        return revokedAt == null && getScopes().containsAll(requestedScopes);
    }

    public void grant(Set<String> requestedScopes, Instant now) {
        Set<String> mergedScopes = new LinkedHashSet<>(getScopes());
        mergedScopes.addAll(requestedScopes);
        this.scopes = join(mergedScopes);
        this.grantedAt = now;
        this.revokedAt = null;
    }

    private static String join(Set<String> values) {
        return values.stream()
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .sorted()
                .collect(Collectors.joining(" "));
    }

    private static Set<String> split(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.split("\\s+"))
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
