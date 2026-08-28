package io.github.brenomega.authkit.domain.mfa.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record MfaLoginVerificationRequest(
        @NotBlank
        @Size(max = 512)
        String mfaToken,

        @NotBlank
        @Size(min = 6, max = 32)
        String code
) {
}
