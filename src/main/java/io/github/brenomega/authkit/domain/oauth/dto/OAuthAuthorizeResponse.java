package io.github.brenomega.authkit.domain.oauth.dto;

/** Carries the exact client redirect produced after authorization. */
public record OAuthAuthorizeResponse(
        String redirectUri,
        String state,
        long expiresIn
) {
}
