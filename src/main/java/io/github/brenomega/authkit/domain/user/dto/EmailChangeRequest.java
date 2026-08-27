package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmailChangeRequest(
        @NotBlank @Email @Size(max = 255) String newEmail,
        @NotBlank @Size(max = 128) String currentPassword,
        @Size(min = 6, max = 32) String mfaCode) {
}
