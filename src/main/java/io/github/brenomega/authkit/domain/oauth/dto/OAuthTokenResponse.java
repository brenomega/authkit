package io.github.brenomega.authkit.domain.oauth.dto;

public record OAuthTokenResponse(
        String accessToken,
        String idToken,
        String tokenType,
        long expiresIn,
        String scope
) {
}
