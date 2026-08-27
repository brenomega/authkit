package io.github.brenomega.authkit.domain.user.dto;

import jakarta.validation.constraints.Size;

/**
 * Per-request proof for sensitive account lifecycle operations.
 */
public record StepUpRequest(
        @Size(max = 128)
        String currentPassword,

        @Size(min = 6, max = 32)
        String mfaCode
) {
    public StepUpRequest(String currentPassword) {
        this(currentPassword, null);
    }
}
