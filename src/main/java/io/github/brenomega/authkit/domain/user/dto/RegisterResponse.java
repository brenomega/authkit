package io.github.brenomega.authkit.domain.user.dto;

public record RegisterResponse(
        String id,
        String email,
        String tenantId
) {
}
