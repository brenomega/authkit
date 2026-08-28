package io.github.brenomega.authkit.domain.mfa.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record MfaVerificationRequest(
        @NotBlank
        @Size(max = 128)
        String currentPassword,

        @NotBlank
        @Size(min = 6, max = 32)
        String code
) {
}
