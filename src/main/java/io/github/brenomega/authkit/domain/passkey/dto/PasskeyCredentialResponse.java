package io.github.brenomega.authkit.domain.passkey.dto;

import java.time.Instant;
import java.util.UUID;

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
