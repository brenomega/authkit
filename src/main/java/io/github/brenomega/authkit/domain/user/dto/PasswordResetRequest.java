package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Carries a one-time recovery secret and a replacement for an existing local password. */
public record PasswordResetRequest(
        @NotBlank String token,
        @NotBlank @Size(min = 12, max = 128) String newPassword
) {
}
