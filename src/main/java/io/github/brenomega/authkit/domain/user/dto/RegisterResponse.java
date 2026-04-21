package io.github.brenomega.authkit.domain.user.dto;

/**
 * DTO returned after a successful user registration.
 *
 * <p>Exposes non-sensitive identification fields and the multi-tenancy ID.</p>
 */
public record RegisterResponse(
        String id,
        String email,
        String tenantId
) {
}
