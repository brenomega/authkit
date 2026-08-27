package io.github.brenomega.authkit.domain.user.dto;

public record AdminAuthenticatorStatus(
        boolean password,
        long activeTotpCredentials,
        long activePasskeys,
        long linkedSocialIdentities
) {}
