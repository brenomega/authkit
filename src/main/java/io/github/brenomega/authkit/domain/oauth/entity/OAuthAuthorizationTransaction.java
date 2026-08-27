package io.github.brenomega.authkit.domain.oauth.entity;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import jakarta.persistence.*;

@Entity
@Table(name = "oauth_authorization_transactions")
public class OAuthAuthorizationTransaction {
    @Id @GeneratedValue(strategy = GenerationType.UUID) private UUID id;
    @Column(name="token_hash",nullable=false,unique=true,length=64,updatable=false) private String tokenHash;
    @Column(name="client_id",nullable=false,length=128,updatable=false) private String clientId;
    @Column(name="redirect_uri",nullable=false,length=512,updatable=false) private String redirectUri;
    @Column(name="scopes",nullable=false,columnDefinition="TEXT",updatable=false) private String scopes;
    @Column(name="state",nullable=false,length=255,updatable=false) private String state;
    @Column(name="nonce",length=255,updatable=false) private String nonce;
    @Column(name="code_challenge",nullable=false,length=128,updatable=false) private String codeChallenge;
    @Column(name="code_challenge_method",nullable=false,length=16,updatable=false) private String codeChallengeMethod;
    @Column(name="created_at",nullable=false,updatable=false) private Instant createdAt;
    @Column(name="expires_at",nullable=false,updatable=false) private Instant expiresAt;
    @Column(name="consumed_at") private Instant consumedAt;
    protected OAuthAuthorizationTransaction() {}
    public OAuthAuthorizationTransaction(String tokenHash,String clientId,String redirectUri,Set<String> scopes,
            String state,String nonce,String codeChallenge,String method,Instant now,Instant expiresAt) {
        this.tokenHash=tokenHash;this.clientId=clientId;this.redirectUri=redirectUri;this.scopes=join(scopes);
        this.state=state;this.nonce=nonce;this.codeChallenge=codeChallenge;this.codeChallengeMethod=method;
        this.createdAt=now;this.expiresAt=expiresAt;
    }
    public UUID getId(){return id;} public String getTokenHash(){return tokenHash;} public String getClientId(){return clientId;}
    public String getRedirectUri(){return redirectUri;} public Set<String> getScopes(){return split(scopes);}
    public String getState(){return state;} public String getNonce(){return nonce;} public String getCodeChallenge(){return codeChallenge;}
    public String getCodeChallengeMethod(){return codeChallengeMethod;} public Instant getExpiresAt(){return expiresAt;}
    public Instant getConsumedAt(){return consumedAt;}
    private static String join(Set<String> v){return v.stream().sorted().collect(Collectors.joining(" "));}
    private static Set<String> split(String v){return Arrays.stream(v.split("\\s+")).filter(s->!s.isBlank()).collect(Collectors.toCollection(LinkedHashSet::new));}
}
