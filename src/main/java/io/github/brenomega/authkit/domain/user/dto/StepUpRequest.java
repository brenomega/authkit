package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Per-request proof for sensitive account lifecycle operations.
 */
public record StepUpRequest(
        @NotBlank
        @Size(max = 128)
        String currentPassword,

        @Size(min = 6, max = 32)
        String mfaCode
) {
    public StepUpRequest(String currentPassword) {
        this(currentPassword, null);
    }
}
