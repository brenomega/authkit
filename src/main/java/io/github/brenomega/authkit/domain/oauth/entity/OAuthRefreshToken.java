package io.github.brenomega.authkit.domain.oauth.entity;

import java.time.Instant;
import java.util.UUID;
import jakarta.persistence.*;

@Entity @Table(name="oauth_refresh_tokens")
public class OAuthRefreshToken {
    @Id @GeneratedValue(strategy=GenerationType.UUID) private UUID id;
    @Column(name="token_hash",nullable=false,unique=true,length=64,updatable=false) private String tokenHash;
    @Column(name="family_id",nullable=false,updatable=false) private UUID familyId;
    @Column(name="created_at",nullable=false,updatable=false) private Instant createdAt;
    @Column(name="expires_at",nullable=false,updatable=false) private Instant expiresAt;
    @Column(name="consumed_at") private Instant consumedAt;
    @Column(name="revoked_at") private Instant revokedAt;
    @Column(name="replaced_token_hash",length=64) private String replacedTokenHash;
    protected OAuthRefreshToken(){}
    public OAuthRefreshToken(String tokenHash,UUID familyId,Instant now,Instant expiresAt){this.tokenHash=tokenHash;this.familyId=familyId;this.createdAt=now;this.expiresAt=expiresAt;}
    public UUID getId(){return id;} public String getTokenHash(){return tokenHash;} public UUID getFamilyId(){return familyId;}
    public Instant getExpiresAt(){return expiresAt;} public Instant getConsumedAt(){return consumedAt;} public Instant getRevokedAt(){return revokedAt;}
    public boolean isActive(Instant now){return consumedAt==null&&revokedAt==null&&expiresAt.isAfter(now);}
    public void consume(Instant now,String replacement){consumedAt=now;replacedTokenHash=replacement;}
    public void revoke(Instant now){if(revokedAt==null)revokedAt=now;}
}
