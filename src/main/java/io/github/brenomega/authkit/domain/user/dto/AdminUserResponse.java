package io.github.brenomega.authkit.domain.user.dto;

import java.time.Instant;
import java.util.UUID;

import io.github.brenomega.authkit.domain.user.enums.Role;
import io.github.brenomega.authkit.domain.user.enums.AccountState;

public record AdminUserResponse(
        UUID id,
        UUID tenantId,
        String email,
        String name,
        Role role,
        AccountState accountState,
        boolean emailConfirmed,
        Instant suspendedAt,
        String suspensionReason,
        Instant deletionRequestedAt,
        Instant deletedAt,
        Instant anonymizedAt
) {
}
