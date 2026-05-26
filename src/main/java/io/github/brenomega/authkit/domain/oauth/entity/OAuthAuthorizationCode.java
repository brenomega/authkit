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
@Table(name = "oauth_authorization_codes")
public class OAuthAuthorizationCode {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "code_hash", nullable = false, unique = true, length = 64, updatable = false)
    private String codeHash;

    @Column(name = "client_id", nullable = false, length = 128, updatable = false)
    private String clientId;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "redirect_uri", nullable = false, length = 512, updatable = false)
    private String redirectUri;

    @Column(name = "scopes", nullable = false, columnDefinition = "TEXT", updatable = false)
    private String scopes;

    @Column(name = "amr", nullable = false, length = 255, updatable = false)
    private String amr;

    @Column(name = "code_challenge", nullable = false, length = 128, updatable = false)
    private String codeChallenge;

    @Column(name = "code_challenge_method", nullable = false, length = 16, updatable = false)
    private String codeChallengeMethod;

    @Column(name = "nonce", length = 255, updatable = false)
    private String nonce;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    protected OAuthAuthorizationCode() {
    }

    public OAuthAuthorizationCode(String codeHash,
                                  String clientId,
                                  UUID userId,
                                  UUID tenantId,
                                  String redirectUri,
                                  Set<String> scopes,
                                  Set<String> amr,
                                  String codeChallenge,
                                  String codeChallengeMethod,
                                  String nonce,
                                  Instant createdAt,
                                  Instant expiresAt) {
        this.codeHash = codeHash;
        this.clientId = clientId;
        this.userId = userId;
        this.tenantId = tenantId;
        this.redirectUri = redirectUri;
        this.scopes = join(scopes);
        this.amr = join(amr);
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.nonce = nonce;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    public UUID getId() {
        return id;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public String getClientId() {
        return clientId;
    }

    public UUID getUserId() {
        return userId;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public Set<String> getScopes() {
        return split(scopes);
    }

    public Set<String> getAmr() {
        return split(amr);
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public String getNonce() {
        return nonce;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }

    private static String join(Set<String> values) {
        return values.stream().sorted().collect(Collectors.joining(" "));
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
