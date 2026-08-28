package io.github.brenomega.authkit.domain.social.dto;

import java.time.Instant;
import java.util.UUID;

/** Describes public metadata for a social identity linked to the current account. */
public record SocialIdentityResponse(UUID id, String providerKey, String issuer, String emailAtLink,
                                     Instant createdAt, Instant lastLoginAt) {}
