package io.github.brenomega.authkit.domain.oauth.dto;

public record OAuthAuthorizeResponse(
        String redirectUri,
        String state,
        long expiresIn
) {
}
