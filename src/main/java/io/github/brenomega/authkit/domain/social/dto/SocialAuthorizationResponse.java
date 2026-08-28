package io.github.brenomega.authkit.domain.social.dto;

/** Carries a provider authorization URL and the remaining ceremony lifetime in seconds. */
public record SocialAuthorizationResponse(String authorizationUrl, long expiresIn) {}
