package io.github.brenomega.authkit.domain.user.dto;

/**
 * Payload describing the public elements of a User.
 */
public record ProfileResponse(
        String id,
        String email,
        String name
) {
}
