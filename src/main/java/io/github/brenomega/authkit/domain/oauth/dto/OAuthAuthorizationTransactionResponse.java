package io.github.brenomega.authkit.domain.oauth.dto;
import java.util.Set;
public record OAuthAuthorizationTransactionResponse(String clientId,String clientDisplayName,Set<String> scopes,boolean consentRequired,long expiresIn){}
