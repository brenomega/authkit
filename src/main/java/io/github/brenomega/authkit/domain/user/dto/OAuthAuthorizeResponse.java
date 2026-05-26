package io.github.brenomega.authkit.domain.user.dto;

public record OAuthAuthorizeResponse(
        String redirectUri,
        String code,
        String state,
        long expiresIn
) {
}
