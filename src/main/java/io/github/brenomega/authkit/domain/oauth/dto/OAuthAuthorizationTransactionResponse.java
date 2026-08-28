package io.github.brenomega.authkit.domain.oauth.dto;
import java.util.Set;

/** Describes a live authorization transaction without exposing its persisted digest or PKCE state. */
public record OAuthAuthorizationTransactionResponse(
        String clientId,
        String clientDisplayName,
        Set<String> scopes,
        boolean consentRequired,
        long expiresIn) {}
