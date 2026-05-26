package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;
import java.util.UUID;

import io.github.brenomega.authkit.domain.user.enums.Role;

public record AdminUserResponse(
        UUID id,
        UUID tenantId,
        String email,
        String name,
        Role role,
        boolean emailConfirmed,
        boolean deleted,
        Instant deletionRequestedAt,
        Instant deletedAt,
        Instant anonymizedAt
) {
}
