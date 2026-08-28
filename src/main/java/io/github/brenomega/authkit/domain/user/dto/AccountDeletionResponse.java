package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;

public record AccountDeletionResponse(
        String status,
        Instant deletionRequestedAt,
        Instant graceExpiresAt,
        Instant deletedAt,
        Instant anonymizedAt
) {
}
