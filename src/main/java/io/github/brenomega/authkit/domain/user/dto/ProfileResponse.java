package io.github.brenomega.authkit.domain.user.dto;

public record ProfileResponse(
        String id,
        String email,
        String name
) {
}
