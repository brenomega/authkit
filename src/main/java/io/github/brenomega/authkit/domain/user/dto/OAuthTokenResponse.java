package io.github.brenomega.authkit.domain.user.dto;

public record OAuthTokenResponse(
        String accessToken,
        String idToken,
        String tokenType,
        long expiresIn,
        String scope
) {
}
