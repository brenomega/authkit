package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;

/** Describes the durable deletion state and the configured grace-period deadline. */
public record AccountDeletionResponse(
        String status,
        Instant deletionRequestedAt,
        Instant graceExpiresAt,
        Instant deletedAt,
        Instant anonymizedAt
) {
}
