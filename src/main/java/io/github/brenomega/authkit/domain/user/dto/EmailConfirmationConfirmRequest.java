package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Carries the one-time secret proving ownership of a registration email. */
public record EmailConfirmationConfirmRequest(
        @NotBlank
        @Size(min = 32, max = 128)
        String token
) {
}
