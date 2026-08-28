package io.github.brenomega.authkit.domain.oauth.dto;

/** Carries tokens issued by the OAuth authorization-code exchange. */
public record OAuthTokenResponse(
        String accessToken,
        String idToken,
        String tokenType,
        long expiresIn,
        String scope
) {
}
