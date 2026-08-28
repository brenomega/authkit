package io.github.brenomega.authkit.domain.user.dto;

/** Identifies a newly created account when stealth-conflict mode permits disclosure. */
public record RegisterResponse(
        String id,
        String email,
        String tenantId
) {
}
