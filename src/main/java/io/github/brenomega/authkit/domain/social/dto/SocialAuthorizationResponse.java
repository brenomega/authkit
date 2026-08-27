package io.github.brenomega.authkit.domain.social.dto;

public record SocialAuthorizationResponse(String authorizationUrl, long expiresIn) {}
