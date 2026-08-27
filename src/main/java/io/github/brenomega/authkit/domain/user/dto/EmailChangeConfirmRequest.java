package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmailChangeConfirmRequest(
        @NotBlank @Size(max = 512) String token) {
}
