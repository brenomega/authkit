package io.github.brenomega.authkit.domain.user.dto;

import java.util.UUID;

import io.github.brenomega.authkit.domain.user.enums.Role;

/** Summarizes a tenant visible to the current administrator. */
public record TenantSummaryResponse(
        UUID tenantId,
        UUID representativeUserId,
        String representativeEmail,
        Role representativeRole
) {
}
