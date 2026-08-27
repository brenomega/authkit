package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmailConfirmationConfirmRequest(
        @NotBlank
        @Size(min = 32, max = 128)
        String token
) {
}
