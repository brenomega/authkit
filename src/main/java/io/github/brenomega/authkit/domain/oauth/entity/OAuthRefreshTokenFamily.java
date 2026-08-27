package io.github.brenomega.authkit.domain.oauth.entity;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import jakarta.persistence.*;

@Entity @Table(name="oauth_refresh_token_families")
public class OAuthRefreshTokenFamily {
    @Id private UUID id;
    @Column(name="user_id",nullable=false,updatable=false) private UUID userId;
    @Column(name="client_id",nullable=false,length=128,updatable=false) private String clientId;
    @Column(name="scopes",nullable=false,columnDefinition="TEXT",updatable=false) private String scopes;
    @Column(name="amr",nullable=false,length=255,updatable=false) private String amr;
    @Column(name="active_token_hash",nullable=false,length=64) private String activeTokenHash;
    @Column(name="created_at",nullable=false,updatable=false) private Instant createdAt;
    @Column(name="expires_at",nullable=false,updatable=false) private Instant expiresAt;
    @Column(name="revoked_at") private Instant revokedAt;
    @Column(name="compromised_at") private Instant compromisedAt;
    protected OAuthRefreshTokenFamily(){}
    public OAuthRefreshTokenFamily(UUID id,UUID userId,String clientId,Set<String> scopes,Set<String> amr,
            String activeTokenHash,Instant now,Instant expiresAt){this.id=id;this.userId=userId;this.clientId=clientId;
        this.scopes=join(scopes);this.amr=join(amr);this.activeTokenHash=activeTokenHash;this.createdAt=now;this.expiresAt=expiresAt;}
    public UUID getId(){return id;} public UUID getUserId(){return userId;} public String getClientId(){return clientId;}
    public Set<String> getScopes(){return split(scopes);} public Set<String> getAmr(){return split(amr);}
    public String getActiveTokenHash(){return activeTokenHash;} public Instant getExpiresAt(){return expiresAt;}
    public Instant getRevokedAt(){return revokedAt;} public Instant getCompromisedAt(){return compromisedAt;}
    public boolean isActive(Instant now){return revokedAt==null&&expiresAt.isAfter(now);}
    public void rotate(String hash){activeTokenHash=hash;}
    public void revoke(Instant now,boolean compromised){if(revokedAt==null)revokedAt=now;if(compromised&&compromisedAt==null)compromisedAt=now;}
    private static String join(Set<String> v){return v.stream().sorted().collect(Collectors.joining(" "));}
    private static Set<String> split(String v){return Arrays.stream(v.split("\\s+")).filter(s->!s.isBlank()).collect(Collectors.toCollection(LinkedHashSet::new));}
}
