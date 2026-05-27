package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmailConfirmationResendRequest(
        @NotBlank
        @Email
        @Size(max = 255)
        String email
) {
}
