package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Completes a password login that was paused for MFA verification.
 */
public record MfaLoginVerificationRequest(
        @NotBlank
        @Size(max = 512)
        String mfaToken,

        @NotBlank
        @Size(min = 6, max = 32)
        String code
) {
}
