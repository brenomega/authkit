package io.github.brenomega.authkit.domain.user.dto;

/** Summarizes authenticator availability without exposing credential material. */
public record AdminAuthenticatorStatus(
        boolean password,
        long activeTotpCredentials,
        long activePasskeys,
        long linkedSocialIdentities
) {}
