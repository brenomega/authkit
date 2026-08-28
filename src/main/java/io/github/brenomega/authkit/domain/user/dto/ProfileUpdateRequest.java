package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Size;

public record ProfileUpdateRequest(
        @Size(max = 100) String name
) {
}
