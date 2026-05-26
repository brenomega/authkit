package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;
import java.util.UUID;

public record PasskeyCredentialResponse(
        UUID id,
        String credentialId,
        String label,
        String transports,
        boolean discoverable,
        boolean backupEligible,
        boolean backedUp,
        Instant createdAt,
        Instant lastUsedAt
) {
}
