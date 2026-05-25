package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;

/**
 * Result of an account deletion/anonymization request.
 */
public record AccountDeletionResponse(
        String status,
        Instant deletionRequestedAt,
        Instant deletedAt,
        Instant anonymizedAt
) {
}
