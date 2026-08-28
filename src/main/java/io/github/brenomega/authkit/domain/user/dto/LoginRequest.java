package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Carries local credentials and privacy-reduced session context for initial authentication. */
public record LoginRequest(
        @NotBlank @Email String email,
        @NotBlank @Size(max = 128) String password
) {
}
