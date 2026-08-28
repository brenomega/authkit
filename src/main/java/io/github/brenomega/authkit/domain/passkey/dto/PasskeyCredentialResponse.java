package io.github.brenomega.authkit.domain.passkey.dto;

import java.time.Instant;
import java.util.UUID;

/** Describes public metadata for an active passkey credential. */
public record PasskeyCredentialResponse(
        UUID id,
        String credentialId,
        String label,
        String transports,
        boolean discoverable,
        Instant createdAt,
        Instant lastUsedAt
) {
}
