package io.github.brenomega.authkit.domain.user.dto;

/** Describes the current account's public profile within its tenant boundary. */
public record ProfileResponse(
        String id,
        String email,
        String name
) {
}
